"""
src/stage2_prefilter/prefilter_engine.py

Upgraded, production-ready Stage-2 Prefilter Engine.

Provides:
 - ProcessTracker: maintains per-PID sliding-window stats (writes, file mods, entropy, extensions, dirs)
 - PrefilterEngine: evaluation logic that applies heuristics and scoring
 - Backwards-compatible function `stage2_prefilter(event)` returning (promote: bool, reasons: list)

Design goals:
 - Thread-safe
 - Configurable thresholds
 - Informative logging
 - Minimal external deps (only stdlib)
 - Metrics-friendly (expose get_metrics())

Notes:
 - This engine expects Stage-1 to provide normalized events with keys like:
   - event_id / EventID (int)
   - type (e.g. "FILE_CREATE" / "NETWORK_CONNECTION")
   - ProcessID / process_id / ProcessId
   - ParentProcessId / parent_process_id
   - TargetFilename / target_filename
   - Message / CommandLine / image / Image
 - Keep tuning thresholds per environment.

"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Set, Tuple, List

logger = logging.getLogger("prefilter_engine")
logger.addHandler(logging.NullHandler())

# Mode-aware prefiltering
try:
    from src.config.mode_config import get_mode_manager, RunMode
    _MODE_MANAGER = get_mode_manager()
    _MODE_AWARE = True
except ImportError:
    _MODE_AWARE = False
    logger.debug("Mode manager not available, running in standard mode")

# ------------------------------------------------------------------
# Defaults / Tunables (environment-specific tuning is expected)
# ------------------------------------------------------------------
DEFAULTS = {
    "ENTROPY_THRESHOLD": 7.9,
    "ENTROPY_VELOCITY_THRESHOLD": 0.8,
    "WRITE_BURST_THRESHOLD": 10.0,
    "FILES_MODIFIED_THRESHOLD": 25,
    "EXTENSION_DIVERSITY_THRESHOLD": 8,
    "DIR_FILE_THRESHOLD": 50,
    "WINDOW_SEC": 30,
    "CLEANUP_SEC": 300,
    "HONEY_DIRS": [r"C:\Honeypots", r"C:\Honeypots"],
    "HONEY_FILES": {"budget.xlsx", "passwords.doc", "backup.zip"},
    "SCORE_PROMOTE_THRESHOLD": 10.0,
    # Enhanced ransomware detection thresholds
    "RANSOM_NOTE_SCORE": 5.0,
    "MASS_FILE_OP_SCORE": 3.0,
    "REGISTRY_PERSISTENCE_SCORE": 4.0,
    "SUSPICIOUS_DOMAIN_SCORE": 6.0,
    "RAPID_EXTENSION_CHANGE_SCORE": 4.0,
    "FILE_DELETE_BURST_THRESHOLD": 10,  # Files deleted in window
}


# Regex patterns for ransomware detection
RANSOM_EXT_PATTERN = re.compile(
    r"\.(crypt|locked|encrypted|zzz|abc|xxx|micro|btc|wallet|vault|encrypted|ecc|ezz|exx|xyz|aaa|zzz|locky|cerber|teslacrypt|petya|wannacry|ryuk|maze|sodinokibi|revil|conti|blackcat|alphv)$",
    re.IGNORECASE,
)
POWERSHELL_SUSPICIOUS = re.compile(
    r"(encodedcommand|downloadstring|frombase64string|invoke-webrequest|iwr|iex|bypass|set-executionpolicy|hidden|windowstyle hidden|noprofile|noninteractive|executionpolicy bypass)",
    re.IGNORECASE,
)
SHADOW_COPY_REGEX = re.compile(r"(vssadmin\s+delete|wmic\s+shadowcopy|wbadmin\s+delete|vss\s+delete|shadowcopy\s+delete)", re.IGNORECASE)
# Ransomware note patterns
RANSOM_NOTE_PATTERN = re.compile(
    r"(readme|decrypt|recover|restore|ransom|payment|bitcoin|btc|crypto|wallet|how to decrypt|your files|encrypted files)",
    re.IGNORECASE,
)
# Suspicious file operations
MASS_FILE_PATTERN = re.compile(
    r"(\.(doc|docx|xls|xlsx|ppt|pptx|pdf|jpg|jpeg|png|gif|zip|rar|7z|txt|rtf|odt|ods|odp))",
    re.IGNORECASE,
)
# Registry persistence patterns
REGISTRY_PERSISTENCE = re.compile(
    r"(runonce|runservices|winlogon|shell|userinit|image file execution)",
    re.IGNORECASE,
)
# Network C2 patterns
SUSPICIOUS_DOMAIN = re.compile(
    r"(tor|onion|bitcoin|payment|ransom|decrypt|recover)\.(onion|bit|tk|ml|ga|cf)",
    re.IGNORECASE,
)

# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for c in freq:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def _now() -> float:
    return time.time()

# ------------------------------------------------------------------
# Tracker
# ------------------------------------------------------------------

@dataclass
class ProcessStats:
    pid: int
    writes_ts: deque = field(default_factory=lambda: deque())         # timestamps of write events
    files_ts: deque = field(default_factory=lambda: deque())          # timestamps of file modifications
    files_seen: deque = field(default_factory=lambda: deque())        # (timestamp, filename)
    files_deleted_ts: deque = field(default_factory=lambda: deque())  # timestamps of file deletions (for window cleanup)
    extensions: Counter = field(default_factory=Counter)             # extension -> count in window
    dirs: Counter = field(default_factory=Counter)                   # directory -> count in window
    entropy_samples: deque = field(default_factory=lambda: deque())   # (timestamp, entropy)
    last_seen: float = field(default_factory=_now)
    image: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None

    def touch(self):
        self.last_seen = _now()


class ProcessTracker:
    def __init__(self, window_sec: int = DEFAULTS["WINDOW_SEC"], cleanup_sec: int = DEFAULTS["CLEANUP_SEC"]):
        self.window = float(window_sec)
        self.cleanup_sec = float(cleanup_sec)
        self._lock = threading.RLock()
        self._stats: Dict[int, ProcessStats] = {}
        self._parent: Dict[int, int] = {}           # pid -> ppid

    def _get(self, pid: int) -> ProcessStats:
        if pid not in self._stats:
            self._stats[pid] = ProcessStats(pid=pid)
        return self._stats[pid]

    def register_process(self, pid: int, ppid: Optional[int], image: Optional[str] = None, cmd: Optional[str] = None):
        if pid is None:
            return
        with self._lock:
            s = self._get(pid)
            if ppid:
                s.parent_pid = int(ppid)
                self._parent[int(pid)] = int(ppid)
            if image:
                s.image = image
            if cmd:
                s.command_line = cmd
            s.touch()

    def update_write(self, pid: int, count: int = 1):
        if pid is None:
            return
        now = _now()
        with self._lock:
            s = self._get(pid)
            for _ in range(count):
                s.writes_ts.append(now)
            s.touch()

    def update_file_mod(self, pid: int, filename: str):
        if pid is None or not filename:
            return
        now = _now()
        ext = _extract_ext(filename)
        d = _extract_dir(filename)
        with self._lock:
            s = self._get(pid)
            s.files_ts.append(now)
            s.files_seen.append((now, filename))
            if ext:
                s.extensions[ext] += 1
            if d:
                s.dirs[d] += 1
            s.touch()

    def update_entropy(self, pid: int, entropy: float):
        if pid is None:
            return
        now = _now()
        with self._lock:
            s = self._get(pid)
            s.entropy_samples.append((now, float(entropy)))
            # limit samples
            while len(s.entropy_samples) > 50:
                s.entropy_samples.popleft()
            s.touch()

    def get_write_rate(self, pid: int) -> float:
        now = _now()
        with self._lock:
            s = self._stats.get(pid)
            if not s:
                return 0.0
            while s.writes_ts and now - s.writes_ts[0] > self.window:
                s.writes_ts.popleft()
            return len(s.writes_ts) / max(1.0, self.window)

    def get_files_modified_count(self, pid: int) -> int:
        now = _now()
        with self._lock:
            s = self._stats.get(pid)
            if not s:
                return 0
            while s.files_ts and now - s.files_ts[0] > self.window:
                s.files_ts.popleft()
            return len(s.files_ts)
    
    def update_file_delete(self, pid: int):
        """Track a file deletion event for the given PID"""
        if pid is None:
            return
        now = _now()
        with self._lock:
            s = self._get(pid)
            s.files_deleted_ts.append(now)
            s.touch()
    
    def get_files_deleted_count(self, pid: int) -> int:
        """Get the count of file deletions for the given PID in the current window"""
        now = _now()
        with self._lock:
            s = self._stats.get(pid)
            if not s:
                return 0
            # Clean up old deletion timestamps outside the window
            while s.files_deleted_ts and now - s.files_deleted_ts[0] > self.window:
                s.files_deleted_ts.popleft()
            return len(s.files_deleted_ts)

    def get_extension_diversity(self, pid: int) -> int:
        now = _now()
        with self._lock:
            s = self._stats.get(pid)
            if not s:
                return 0
            # purge old entries from files_seen and recompute extension diversity
            while s.files_seen and now - s.files_seen[0][0] > self.window:
                ts, fname = s.files_seen.popleft()
                ext = _extract_ext(fname)
                if ext and s.extensions.get(ext):
                    s.extensions[ext] -= 1
                    if s.extensions[ext] <= 0:
                        del s.extensions[ext]
            return len(s.extensions)

    def get_top_dir_count(self, pid: int) -> Tuple[Optional[str], int]:
        now = _now()
        with self._lock:
            s = self._stats.get(pid)
            if not s:
                return None, 0
            # purge old dir counts by re-evaluating from files_seen (cheap enough in window)
            # rebuild dirs
            dirs = Counter()
            for ts, fname in s.files_seen:
                if now - ts <= self.window:
                    d = _extract_dir(fname)
                    if d:
                        dirs[d] += 1
            if not dirs:
                return None, 0
            top_dir, cnt = dirs.most_common(1)[0]
            return top_dir, cnt

    def get_entropy_velocity(self, pid: int) -> float:
        now = _now()
        with self._lock:
            s = self._stats.get(pid)
            if not s or len(s.entropy_samples) < 3:
                return 0.0
            # keep only recent samples
            samples = [(t, v) for t, v in s.entropy_samples if now - t <= max(self.window, 60)]
            if len(samples) < 3:
                return 0.0
            times = [t for t, _ in samples]
            vals = [v for _, v in samples]
            if times[-1] == times[0]:
                return 0.0
            vel = (vals[-1] - vals[0]) / (times[-1] - times[0])
            return vel

    def is_honeypot_accessed(self, pid: int, honey_dirs: List[str], honey_files: Set[str]) -> bool:
        with self._lock:
            s = self._stats.get(pid)
            if not s:
                return False
            for _, fname in s.files_seen:
                low = fname.lower()
                if any(hd.lower() in low for hd in honey_dirs):
                    return True
                if low.split("\\")[-1] in honey_files:
                    return True
            return False

    def get_parent_chain(self, pid: int, max_depth: int = 10) -> List[int]:
        chain = []
        with self._lock:
            cur = pid
            while cur and cur in self._parent and len(chain) < max_depth:
                p = self._parent.get(cur)
                if not p:
                    break
                chain.append(p)
                cur = p
        return chain

    def cleanup_old(self):
        now = _now()
        with self._lock:
            stale = [pid for pid, s in self._stats.items() if now - s.last_seen > self.cleanup_sec]
            for pid in stale:
                del self._stats[pid]
                if pid in self._parent:
                    del self._parent[pid]

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "tracked_pids": len(self._stats),
            }


# ------------------------------------------------------------------
# Helpers for filename/extraction
# ------------------------------------------------------------------

def _extract_ext(path: str) -> Optional[str]:
    try:
        idx = path.rfind('.')
        if idx == -1:
            return None
        return path[idx:].lower()
    except Exception:
        return None


def _extract_dir(path: str) -> Optional[str]:
    try:
        p = path.replace('/', '\\')
        idx = p.rfind('\\')
        if idx == -1:
            return None
        return p[:idx].lower()
    except Exception:
        return None


# ------------------------------------------------------------------
# Prefilter Engine
# ------------------------------------------------------------------

class PrefilterEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None, enable_correlation: bool = True):
        cfg = dict(DEFAULTS)
        if config:
            cfg.update(config)
        self.cfg = cfg
        self.tracker = ProcessTracker(window_sec=cfg["WINDOW_SEC"], cleanup_sec=cfg["CLEANUP_SEC"])
        
        # Initialize correlation engine for cross-PID analysis
        self.enable_correlation = enable_correlation
        if enable_correlation:
            try:
                from .correlation_engine import get_correlation_engine
                self.correlation_engine = get_correlation_engine()
            except Exception as e:
                logger.warning(f"Correlation engine not available: {e}")
                self.correlation_engine = None
                self.enable_correlation = False
        else:
            self.correlation_engine = None
        self._lock = threading.RLock()
        
        # Mode awareness
        self._mode_aware = _MODE_AWARE

    def _should_filter_benign(self) -> bool:
        """Check if benign events should be filtered based on current mode"""
        if not self._mode_aware:
            return True  # Default: filter benign in production
        
        try:
            return _MODE_MANAGER.is_production_mode()
        except Exception as e:
            logger.debug(f"Error checking mode: {e}, defaulting to production filtering")
            return True

    def process_event(self, event: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Main entry. Accepts a raw/normalized event from Stage-1 and returns (promote, reasons).
        promote: bool — whether event/process should be promoted to Stage-3
        reasons: list[str] — explanation for promotion (empty if promote==False)
        
        In dataset collection mode, all events are promoted for feature extraction.
        In production mode, only suspicious events are promoted.
        """
        # In dataset collection mode, pass through all events
        if self._mode_aware and _MODE_MANAGER.is_dataset_mode():
            logger.debug("Dataset mode: passing through event without filtering")
            return (True, ["dataset_collection_mode"])
        
        self.tracker.cleanup_old()
        reasons: List[str] = []
        score = 0.0  # Initialize score early - it may be used in early checks

        # Normalize keys we commonly expect
        event_id = None
        for k in ("event_id", "EventID", "EventId", "id", "Id"):
            if k in event:
                try:
                    event_id = int(event[k])
                    break
                except Exception:
                    pass
        # fallback to type mapping
        ev_type = str(event.get("type") or event.get("Type") or "").upper()

        # process ids
        pid = None
        for k in ("process_id", "ProcessID", "ProcessId", "pid"):
            if k in event:
                try:
                    pid = int(event[k])
                    break
                except Exception:
                    pass
        ppid = None
        for k in ("parent_process_id", "ParentProcessId", "ParentPID", "ppid"):
            if k in event:
                try:
                    ppid = int(event[k])
                    break
                except Exception:
                    pass

        image = event.get("image") or event.get("Image") or event.get("image_name") or event.get("ImageName")
        cmd = event.get("command_line") or event.get("CommandLine") or event.get("Message") or event.get("message")

        # register process meta
        if pid:
            self.tracker.register_process(pid, ppid, image=image, cmd=cmd)

        # Quick checks: Suspicious PowerShell or Shadow-copy command in commandline
        if cmd and isinstance(cmd, str):
            if POWERSHELL_SUSPICIOUS.search(cmd):
                reasons.append("suspicious_powershell_cmdline")
            if SHADOW_COPY_REGEX.search(cmd):
                reasons.append("shadow_copy_deletion_cmdline")

        # ------------------ FILE CREATE / MODIFY handling ------------------
        # Many Stage-1 variants provide event types like "FILE_CREATE", EventID 11, or messages with TargetFilename
        target = None
        for k in ("target_filename", "TargetFilename", "TargetFile", "path", "Path"):
            if k in event and event.get(k):
                target = event.get(k)
                break

        # If we have a filename, update tracker
        if target and pid:
            try:
                # update_file_mod only accepts pid and filename (no is_delete parameter)
                self.tracker.update_file_mod(pid, str(target))
            except Exception:
                logger.exception("tracker.update_file_mod failed")

            # Ransom extension heuristic
            if RANSOM_EXT_PATTERN.search(str(target)):
                reasons.append("ransom_extension_detected")
                score += 8.0  # High score for ransom extensions
            
            # Check for ransom note creation (README files with suspicious content)
            target_lower = str(target).lower()
            if any(note in target_lower for note in ["readme", "decrypt", "recover", "restore", "how_to_decrypt"]):
                if RANSOM_NOTE_PATTERN.search(str(target)):
                    reasons.append("ransom_note_file_created")
                    score += self.cfg.get("RANSOM_NOTE_SCORE", 5.0)
            
            # Mass file operation detection (targeting common file types)
            if MASS_FILE_PATTERN.search(str(target)):
                # If we're seeing many different file types being modified, it's suspicious
                if pid:
                    ext_div = self.tracker.get_extension_diversity(pid)
                    if ext_div >= 5:  # Multiple different file types
                        reasons.append("mass_file_type_targeting")
                        score += self.cfg.get("MASS_FILE_OP_SCORE", 3.0)

        # Provide entropy sample if provided (some Stage-1 components may compute entropy)
        ent = None
        for k in ("entropy", "file_entropy", "entropy_score"):
            if k in event and event.get(k) is not None:
                try:
                    ent = float(event[k])
                except Exception:
                    ent = None
                break
        if ent is not None and pid:
            self.tracker.update_entropy(pid, ent)
            # absolute entropy
            if ent >= self.cfg["ENTROPY_THRESHOLD"]:
                reasons.append("high_absolute_entropy")

        # If Stage-1 provided raw bytes (rare), compute entropy here
        if event.get("file_bytes") and pid:
            try:
                ent2 = shannon_entropy(event.get("file_bytes"))
                self.tracker.update_entropy(pid, ent2)
                if ent2 >= self.cfg["ENTROPY_THRESHOLD"]:
                    reasons.append("high_entropy_from_bytes")
            except Exception:
                logger.exception("Entropy calc failed")

        # Write detection via message content or event type
        msg = str(event.get("Message") or event.get("message") or "")
        if "write" in msg.lower() or ev_type in ("FILE_CREATE", "FILE_WRITE", "FILE_WRITE_DATA"):
            if pid:
                self.tracker.update_write(pid)

        # Network events might not affect file heuristics but check suspicious destinations if needed
        # ------------------ Heuristic scoring ------------------
        # (score already initialized at start of method)

        # High write burst
        if pid:
            write_rate = self.tracker.get_write_rate(pid)
            if write_rate >= self.cfg["WRITE_BURST_THRESHOLD"]:
                reasons.append(f"write_burst_{write_rate:.1f}_wps")
                score += (write_rate / max(1.0, self.cfg["WRITE_BURST_THRESHOLD"])) * 3.0

            files_mod = self.tracker.get_files_modified_count(pid)
            if files_mod >= self.cfg["FILES_MODIFIED_THRESHOLD"]:
                reasons.append(f"files_modified_{files_mod}_in_window")
                score += 3.0

            ext_div = self.tracker.get_extension_diversity(pid)
            if ext_div >= self.cfg["EXTENSION_DIVERSITY_THRESHOLD"]:
                reasons.append(f"extension_diversity_{ext_div}")
                score += 2.0

            top_dir, dir_count = self.tracker.get_top_dir_count(pid)
            if dir_count >= self.cfg["DIR_FILE_THRESHOLD"]:
                reasons.append(f"mass_mod_in_dir:{top_dir}#{dir_count}")
                score += 3.0

            # entropy velocity
            ent_vel = self.tracker.get_entropy_velocity(pid)
            if ent_vel >= self.cfg["ENTROPY_VELOCITY_THRESHOLD"]:
                reasons.append(f"entropy_velocity_{ent_vel:.3f}")
                score += 4.0

            # honeypot
            if self.tracker.is_honeypot_accessed(pid, self.cfg["HONEY_DIRS"], set(self.cfg["HONEY_FILES"])):
                reasons.append("honeypot_touched")
                score += 10.0

        # Commandline/shell heuristics
        if cmd and isinstance(cmd, str):
            if POWERSHELL_SUSPICIOUS.search(cmd):
                score += 2.5
            if SHADOW_COPY_REGEX.search(cmd):
                score += 8.0

        # Parent chain heuristics: if parent chain already has high activity, boost score
        if pid:
            parents = self.tracker.get_parent_chain(pid)
            if parents:
                # if any parent has writes recently, boost
                for pp in parents:
                    if self.tracker.get_write_rate(pp) > (self.cfg["WRITE_BURST_THRESHOLD"] / 2):
                        reasons.append(f"suspicious_parent_{pp}")
                        score += 2.0

        # Commandline that looks like downloader/dropper
        if cmd and isinstance(cmd, str):
            lowered = cmd.lower()
            if "download" in lowered or "curl" in lowered or "fetch" in lowered:
                reasons.append("network_downloader_cmd")
                score += 1.5
        
        # Registry persistence detection
        if ev_type in ("REGISTRY", "REGISTRY_EVENT", "REGISTRY_SET_VALUE", "REGISTRY_CREATE_KEY") or "registry" in ev_type.lower():
            target_obj = event.get("TargetObject") or event.get("target_object") or ""
            if target_obj and REGISTRY_PERSISTENCE.search(str(target_obj)):
                reasons.append("registry_persistence_attempt")
                score += self.cfg.get("REGISTRY_PERSISTENCE_SCORE", 4.0)
        
        # Network connection to suspicious domains
        if ev_type in ("NETWORK", "NETWORK_CONNECT", "NETWORK_CONNECTION") or "network" in ev_type.lower():
            dest_ip = event.get("DestinationIp") or event.get("destination_ip") or ""
            dest_host = event.get("DestinationHostname") or event.get("destination_hostname") or ""
            if dest_host and SUSPICIOUS_DOMAIN.search(str(dest_host)):
                reasons.append("suspicious_c2_domain")
                score += self.cfg.get("SUSPICIOUS_DOMAIN_SCORE", 6.0)
        
        # File deletion burst detection (ransomware often deletes originals)
        if ev_type in ("FILE_DELETE", "FILE_DELETE_DETECTED") or "delete" in ev_type.lower():
            if pid:
                # Track the deletion event
                self.tracker.update_file_delete(pid)
                # Check if we've hit the threshold
                files_deleted = self.tracker.get_files_deleted_count(pid)
                if files_deleted >= self.cfg.get("FILE_DELETE_BURST_THRESHOLD", 10):
                    reasons.append(f"file_deletion_burst_{files_deleted}_files")
                    score += 4.0
        
        # Cross-PID correlation analysis (for coordinated attacks)
        correlation_boost = 0.0
        correlation_patterns = []
        if self.enable_correlation and self.correlation_engine and pid:
            try:
                # Update correlation engine with this process activity
                self.correlation_engine.update_process_activity(
                    pid=pid,
                    parent_pid=ppid,
                    image_path=image or "",
                    filepath=target,
                    event_type=ev_type,
                    suspicious_score=score,
                    suspicious_flags=reasons
                )
                
                # Detect correlation patterns
                patterns = self.correlation_engine.detect_correlations(pid)
                if patterns:
                    correlation_patterns = patterns
                    # Boost score for correlated activities
                    max_confidence = max([p.confidence for p in patterns], default=0.0)
                    if max_confidence > 0.5:
                        correlation_boost = max_confidence * 5.0  # Up to 5.0 points boost
                        reasons.append(f"correlated_activity_{len(patterns)}_patterns")
                        score += correlation_boost
                        logger.info(
                            f"Correlation detected for PID {pid}: {len(patterns)} patterns, "
                            f"confidence={max_confidence:.2f}, boost=+{correlation_boost:.2f}"
                        )
            except Exception:
                logger.debug("Correlation analysis failed (non-fatal)", exc_info=True)

        # Final decision — promote defined FIRST
        
        promote = False
        hard_flags = {"honeypot_touched", "shadow_copy_deletion_cmdline", "ransom_extension_detected"}
        if any(r for r in reasons if any(h in r for h in hard_flags)):
            promote = True
        elif score >= self.cfg["SCORE_PROMOTE_THRESHOLD"]:
            promote = True

        # ALWAYS attach reasons to event for Stage 3 feature extraction
        # Stage 3 needs reasons even for non-promoted events to build comprehensive feature vectors
        if reasons:
            event["__reasons"] = reasons.copy()
            event["__score"] = score  # Also attach score for Stage 3 ML model
        
        # Attach correlation data to event for Stage 3 (if available)
        if correlation_patterns:
            event["__correlation_patterns"] = [
                {
                    "type": p.pattern_type,
                    "confidence": p.confidence,
                    "pids": p.pids,
                    "evidence": p.evidence
                }
                for p in correlation_patterns
            ]
            event["__correlation_boost"] = correlation_boost

        # Optional: always mark event as processed for total count
        event["__processed"] = True

        return promote, reasons

    def get_metrics(self) -> Dict[str, Any]:
        m = dict(self.cfg)
        m.update(self.tracker.get_metrics())
        return m


# ------------------------------------------------------------------
# Backwards-compatible module-level API
# ------------------------------------------------------------------

_ENGINE = PrefilterEngine()


def stage2_prefilter(event: Dict[str, Any]) -> bool:
    """
    Backwards-compatible: returns True if event should be promoted (suspicious).
    Also logs reasons at debug level.
    """
    try:
        promote, reasons = _ENGINE.process_event(event)
        pid = event.get("ProcessID") or event.get("process_id") or event.get("pid")
        score = event.get("__score", 0.0)
        
        if promote:
            logger.warning("PREFILTER PROMOTE pid=%s score=%.2f reasons=%s", pid, score, reasons)
        else:
            # Log high-scoring events that didn't quite make threshold (for tuning)
            if score >= 5.0:
                logger.info("PREFILTER near-threshold pid=%s score=%.2f threshold=%.2f reasons=%s", 
                           pid, score, _ENGINE.cfg["SCORE_PROMOTE_THRESHOLD"], reasons)
            else:
                logger.debug("PREFILTER ignore pid=%s score=%.2f reasons=%s", pid, score, reasons)
        return promote
    except Exception:
        logger.exception("stage2_prefilter failed")
        return False


def get_engine_metrics() -> Dict[str, Any]:
    return _ENGINE.get_metrics()
