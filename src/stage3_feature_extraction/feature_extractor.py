"""
Real-Time Feature Extractor for Stage 3

Tracks per-PID features in real-time and extracts comprehensive feature vectors
for ML scoring. Implements all features from the master feature list.
"""

import os
import time
import threading
import hashlib
import re
from collections import deque, defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Set, Tuple
from pathlib import Path
import logging

logger = logging.getLogger("stage3_feature_extractor")

# Performance optimizations
try:
    from utils.performance_cache import cached_process_info, cached_file_stat
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False
    # Fallback decorators that do nothing
    def cached_process_info(ttl=None):
        def decorator(func):
            return func
        return decorator
    def cached_file_stat(ttl=None):
        def decorator(func):
            return func
        return decorator

# Windows API imports for process querying (optional)
WINDOWS_AVAILABLE = False
try:
    import win32api
    import win32process
    import win32con
    WINDOWS_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ProcessFeatures:
    """Tracks all features for a single process (PID) with lifecycle aggregation"""
    pid: int
    start_time: float
    image_path: str = ""
    command_line: str = ""
    parent_pid: Optional[int] = None
    
    # CPU/RAM metrics (time series) - Extended windows
    cpu_samples: deque = field(default_factory=lambda: deque(maxlen=300))  # Last 5 minutes (was 60s)
    ram_samples: deque = field(default_factory=lambda: deque(maxlen=300))
    cpu_baseline: float = 0.0
    ram_baseline: float = 0.0
    
    # Process metrics - Extended windows
    thread_count_samples: deque = field(default_factory=lambda: deque(maxlen=300))
    handle_count_samples: deque = field(default_factory=lambda: deque(maxlen=300))
    initial_threads: int = 0
    initial_handles: int = 0
    
    # File I/O metrics - Lifecycle tracking
    total_bytes_written: int = 0
    files_created: Set[str] = field(default_factory=set)
    files_modified: Set[str] = field(default_factory=set)
    files_deleted: Set[str] = field(default_factory=set)
    file_entropy_samples: deque = field(default_factory=lambda: deque(maxlen=500))  # Extended
    file_write_timestamps: deque = field(default_factory=lambda: deque(maxlen=5000))  # Extended
    
    # Lifecycle aggregation - Cumulative metrics over process lifetime
    lifecycle_file_creates: List[float] = field(default_factory=list)  # Timestamps for lifecycle analysis
    lifecycle_file_deletes: List[float] = field(default_factory=list)
    lifecycle_network_conns: List[float] = field(default_factory=list)
    lifecycle_registry_mods: List[float] = field(default_factory=list)
    lifecycle_peak_file_rate: float = 0.0  # Peak files/second over lifecycle
    lifecycle_total_events: int = 0  # Total events across lifecycle
    
    # Signature/Trust
    is_signed: Optional[bool] = None
    is_microsoft_signed: Optional[bool] = None
    cert_mismatch: bool = False
    
    # Process tree
    parent_chain: List[int] = field(default_factory=list)
    child_pids: Set[int] = field(default_factory=set)
    spawn_count: int = 0
    
    # Network
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    dns_lookups: List[str] = field(default_factory=list)
    sockets_created: int = 0
    ports_touched: Set[int] = field(default_factory=set)
    destination_ips: Set[str] = field(default_factory=set)
    
    # Path/Working directory
    working_directory: str = ""
    executable_path: str = ""
    path_anomaly: bool = False
    
    # Memory
    memory_regions: List[Dict[str, Any]] = field(default_factory=list)
    executable_memory_regions: int = 0
    memory_entropy_samples: deque = field(default_factory=lambda: deque(maxlen=50))
    pe_header_mismatch: bool = False
    unsigned_image_mapped: bool = False
    
    # Thread anomalies
    thread_start_addresses: List[int] = field(default_factory=list)
    suspicious_thread_starts: int = 0
    
    # DLL/Module loading
    loaded_modules: Set[str] = field(default_factory=set)
    suspicious_dlls: Set[str] = field(default_factory=set)
    dll_load_anomaly_score: float = 0.0
    
    # API calls
    api_call_counts: Counter = field(default_factory=Counter)
    crypt_api_calls: int = 0
    virtualalloc_calls: int = 0
    writeprocessmemory_calls: int = 0
    createremotethread_calls: int = 0
    
    # Privileges
    privilege_escalations: int = 0
    token_manipulations: int = 0
    unexpected_privileges: Set[str] = field(default_factory=set)
    
    # Registry
    registry_modifications: List[str] = field(default_factory=list)
    suspicious_registry_keys: Set[str] = field(default_factory=set)
    
    # Scheduled tasks
    scheduled_task_attempts: int = 0
    
    # Process hollowing/injection
    created_suspended: bool = False
    ntunmapview_calls: int = 0
    large_writeprocessmemory: int = 0
    thread_resume_sequences: int = 0
    
    # File patterns
    file_renames: List[Tuple[str, str]] = field(default_factory=list)  # (old, new)
    extension_changes: Counter = field(default_factory=Counter)
    content_rewrite_patterns: int = 0
    
    # Honeypot
    honeypot_accesses: int = 0
    
    # User interactivity
    gui_access: bool = False
    clipboard_access: bool = False
    user_interactivity_anomaly: bool = False
    
    # Temporal correlation - Extended window
    spike_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))  # Extended
    
    # Baseline deviation
    baseline_deviation_score: float = 0.0
    
    # Event tracking for diagnostics
    event_types_seen: Set[str] = field(default_factory=set)  # Track event types seen
    event_count: int = 0  # Total events processed for this PID
    
    # Last update time
    last_update: float = field(default_factory=time.time)
    
    # Sliding window metrics - Multiple time windows for burstiness detection
    short_window_writes: deque = field(default_factory=lambda: deque(maxlen=100))  # 10-30s window
    medium_window_writes: deque = field(default_factory=lambda: deque(maxlen=300))  # 1-5min window
    long_window_writes: deque = field(default_factory=lambda: deque(maxlen=900))  # 5-15min window
    
    def update_timestamp(self):
        self.last_update = time.time()
    
    def update_peak_file_rate(self):
        """Update peak file creation rate over lifecycle using sliding windows"""
        if not self.lifecycle_file_creates:
            self.lifecycle_peak_file_rate = 0.0
            return
        
        # Calculate peak rate over rolling 30-second windows
        timestamps = sorted(self.lifecycle_file_creates[-200:])  # Last 200 file creates
        if len(timestamps) < 2:
            self.lifecycle_peak_file_rate = float(len(timestamps))
            return
        
        max_rate = 0.0
        window_sec = 30.0
        for i, start_ts in enumerate(timestamps):
            end_ts = start_ts + window_sec
            count = sum(1 for ts in timestamps[i:] if ts <= end_ts)
            rate = count / window_sec
            max_rate = max(max_rate, rate)
        
        self.lifecycle_peak_file_rate = max_rate


class FeatureExtractor:
    """
    Real-time feature extractor that maintains per-PID feature state
    and extracts feature vectors for ML scoring.
    """
    
    # Suspicious registry keys
    SUSPICIOUS_REGISTRY_KEYS = {
        r'\\Run\\', r'\\RunOnce\\', r'\\Winlogon\\',
        r'\\Services\\', r'\\Task Scheduler\\'
    }
    
    # Known Windows paths
    WINDOWS_PATHS = {
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
        r'C:\Program Files',
        r'C:\Program Files (x86)',
    }
    
    # Suspicious DLLs
    SUSPICIOUS_DLLS = {
        'kernel32.dll', 'ntdll.dll',  # Normal but watch for abuse
    }
    
    def __init__(self, window_sec: int = 1800, cleanup_sec: int = 3600):
        """
        Args:
            window_sec: Time window for feature tracking (default 30 minutes - was 5 min)
            cleanup_sec: Cleanup processes older than this (default 60 minutes - was 10 min)
        """
        self.window_sec = window_sec
        self.cleanup_sec = cleanup_sec
        self.processes: Dict[int, ProcessFeatures] = {}
        self._lock = threading.RLock()
        
        # Cross-PID tracking - Parent-child relationships
        self.parent_to_children: Dict[int, Set[int]] = defaultdict(set)  # parent_pid -> {child_pids}
        self.pid_to_process: Dict[int, ProcessFeatures] = {}  # Quick lookup for cross-PID aggregation
        
        # Sibling process tracking (processes spawned within time window)
        self.temporal_siblings: Dict[int, List[Tuple[int, float]]] = defaultdict(list)  # pid -> [(sibling_pid, time_delta)]
        
        # Baseline for process names (for deviation scoring)
        self.process_baselines: Dict[str, Dict[str, float]] = defaultdict(lambda: {
            'avg_cpu': 0.0,
            'avg_ram': 0.0,
            'avg_threads': 0.0,
            'sample_count': 0,
            'avg_file_rate': 0.0,
            'avg_network_rate': 0.0,
        })
        
        # Honeypot directories (from Stage 2 config)
        self.honeypot_dirs: Set[str] = {
            r'C:\Honeypots',
            r'C:\Users\Public\Honeypots'
        }
        
        # Time window configurations for different metrics
        self.short_window_sec = 30.0   # 30 seconds - for immediate burst detection
        self.medium_window_sec = 300.0  # 5 minutes - for medium-term patterns
        self.long_window_sec = 1800.0   # 30 minutes - for long-term trends
        
        # Background cleanup thread
        self._cleanup_interval_sec = min(120.0, cleanup_sec / 10.0)  # Run cleanup every 2min
        self._cleanup_thread = None
        self._cleanup_stop_event = threading.Event()
        self._last_cleanup_time = time.time()
        
        logger.info(f"FeatureExtractor initialized (window={window_sec}s, cleanup={cleanup_sec}s, cleanup_interval={self._cleanup_interval_sec}s)")
    
    def _query_process_info_from_os_cached(self, pid: int) -> Optional[Dict[str, Any]]:
        """Cached version of process info query"""
        if CACHE_AVAILABLE:
            try:
                from utils.performance_cache import _process_info_cache
                cache_key = f"process_{pid}"
                cached = _process_info_cache.get(cache_key)
                if cached is not None:
                    return cached
            except Exception:
                pass
        
        # Not in cache or cache unavailable, query OS
        result = self._query_process_info_from_os_impl(pid)
        
        # Store in cache if available
        if CACHE_AVAILABLE and result is not None:
            try:
                from utils.performance_cache import _process_info_cache
                cache_key = f"process_{pid}"
                _process_info_cache.set(cache_key, result)
            except Exception:
                pass
        
        return result
    
    def _query_process_info_from_os_impl(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Query process information from Windows OS when EventID 1 is missing.
        This helps initialize process features even when we only see network/file events.
        
        Returns:
            Dict with process info (image_path, command_line, parent_pid) or None if query fails
        """
        if not WINDOWS_AVAILABLE:
            return None
        
        try:
            # Open process handle with minimal permissions
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            
            h_process = win32api.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not h_process:
                return None
            
            result = {
                "image_path": "",
                "command_line": "",
                "parent_pid": None
            }
            
            try:
                # Get process image path
                try:
                    # QueryFullProcessImageName requires Windows Vista+
                    if hasattr(win32process, 'QueryFullProcessImageName'):
                        image_path = win32process.QueryFullProcessImageName(h_process, 0)
                        result["image_path"] = image_path
                except Exception:
                    pass
                
                # Get parent process ID (requires PROCESS_QUERY_INFORMATION)
                try:
                    # GetParentProcessId is available in newer pywin32 versions
                    if hasattr(win32process, 'GetParentProcessId'):
                        parent_pid = win32process.GetParentProcessId(h_process)
                        result["parent_pid"] = parent_pid
                except Exception:
                    pass
                
                # Command line is harder to get without more permissions, skip for now
                # Would require PROCESS_QUERY_LIMITED_INFORMATION and NtQueryInformationProcess
                
            finally:
                try:
                    win32api.CloseHandle(h_process)
                except Exception:
                    pass
            
            return result if result.get("image_path") or result.get("parent_pid") else None
                
        except Exception as e:
            logger.debug(f"Failed to query process info from OS for PID {pid}: {e}")
            return None
    
    def process_event(self, event: Dict[str, Any]) -> None:
        """
        Process an event and update feature tracking for the PID.
        
        This method is called continuously for ALL events (not just promoted ones)
        to build per-PID feature profiles over time. It is idempotent - safe to
        call multiple times with the same event.
        
        Called from:
        - UnifiedEDRLauncher: Continuously feeds all events (promoted and non-promoted)
        - Stage3Engine.process_event: Called again on promotion (idempotent, ensures update)
        """
        try:
            # Extract PID
            pid = None
            for k in ("ProcessID", "ProcessId", "process_id", "pid"):
                if k in event:
                    try:
                        pid = int(event[k])
                        break
                    except (ValueError, TypeError):
                        continue
            
            if not pid:
                return
            
            # Get or create ProcessFeatures
            with self._lock:
                if pid not in self.processes:
                    # Check if this is a Process Create event (EventID 1)
                    event_type = event.get("type") or event.get("EventID") or event.get("event_id")
                    is_process_create = (
                        event_type == 1 or 
                        str(event_type).upper() == "PROCESS_CREATE" or
                        "PROCESS_CREATE" in str(event_type).upper()
                    )
                    
                    # Initialize process features
                    image_path = event.get("Image") or event.get("image") or ""
                    command_line = event.get("CommandLine") or event.get("command_line") or ""
                    parent_pid = event.get("ParentProcessId") or event.get("parent_process_id")
                    
                    # If not Process Create event and missing info, try to query from OS (with caching)
                    if not is_process_create and (not image_path or not parent_pid):
                        try:
                            os_info = self._query_process_info_from_os_cached(pid)
                        except Exception as e:
                            logger.debug(f"OS query failed for PID {pid}: {e}")
                            os_info = None
                        if os_info:
                            if not image_path and os_info.get("image_path"):
                                image_path = os_info["image_path"]
                            if not parent_pid and os_info.get("parent_pid"):
                                parent_pid = os_info["parent_pid"]
                            if not command_line and os_info.get("command_line"):
                                command_line = os_info["command_line"]
                            logger.debug(f"Stage3: Queried OS for PID {pid} info (EventID 1 missing)")
                    
                    pf_new = ProcessFeatures(
                        pid=pid,
                        start_time=time.time(),
                        image_path=image_path,
                        command_line=command_line,
                        parent_pid=parent_pid
                    )
                    self.processes[pid] = pf_new
                    self.pid_to_process[pid] = pf_new
                    
                    # Track parent-child relationship for cross-PID features
                    if parent_pid:
                        self.parent_to_children[parent_pid].add(pid)
                        # Track as sibling if parent has other children
                        if parent_pid in self.parent_to_children:
                            siblings = self.parent_to_children[parent_pid] - {pid}
                            if siblings:
                                current_time = time.time()
                                for sibling_pid in siblings:
                                    if sibling_pid in self.processes:
                                        sibling_pf = self.processes[sibling_pid]
                                        time_delta = abs(current_time - sibling_pf.start_time)
                                        if time_delta < 60.0:  # Within 60 seconds = temporal siblings
                                            self.temporal_siblings[pid].append((sibling_pid, time_delta))
                                            self.temporal_siblings[sibling_pid].append((pid, time_delta))
                
                pf = self.processes[pid]
                pf.update_timestamp()
                
                # Track event type for diagnostics
                event_type = event.get("type") or event.get("EventID") or event.get("event_id") or "UNKNOWN"
                if isinstance(event_type, int):
                    event_type = f"EventID_{event_type}"
                pf.event_types_seen.add(str(event_type))
                pf.event_count += 1
                pf.lifecycle_total_events += 1
            
            # Update features based on event type
            self._update_from_event(pf, event)
            
        except Exception:
            logger.exception(f"Error processing event in FeatureExtractor: {event.get('EventID', 'unknown')}")
    
    def _update_from_event(self, pf: ProcessFeatures, event: Dict[str, Any]) -> None:
        """Update ProcessFeatures from event data"""
        try:
            # File operations with lifecycle tracking
            target_file = event.get("TargetFilename") or event.get("target_filename")
            current_time = time.time()
            if target_file:
                event_type = str(event.get("type") or event.get("EventID") or "").upper()
                
                if "CREATE" in event_type or event.get("EventID") == 11:
                    pf.files_created.add(target_file)
                    # Lifecycle tracking
                    pf.lifecycle_file_creates.append(current_time)
                    # Sliding window tracking
                    pf.short_window_writes.append(current_time)
                    pf.medium_window_writes.append(current_time)
                    pf.long_window_writes.append(current_time)
                elif "MODIFY" in event_type or "WRITE" in event_type or event.get("EventID") == 11:
                    pf.files_modified.add(target_file)
                    # Track write timestamps for burstiness (extended windows)
                    pf.file_write_timestamps.append(current_time)
                    # Lifecycle tracking
                    pf.lifecycle_file_creates.append(current_time)
                    # Sliding window tracking
                    pf.short_window_writes.append(current_time)
                    pf.medium_window_writes.append(current_time)
                    pf.long_window_writes.append(current_time)
                    # Update peak rate periodically (every 10 file operations for efficiency)
                    if len(pf.lifecycle_file_creates) % 10 == 0:
                        pf.update_peak_file_rate()
                elif "DELETE" in event_type:
                    pf.files_deleted.add(target_file)
                    # Lifecycle tracking
                    pf.lifecycle_file_deletes.append(current_time)
                
                # Check for file rename pattern
                if "RENAME" in event_type or "MOVED" in event_type:
                    old_file = event.get("SourceFilename") or ""
                    if old_file and target_file:
                        pf.file_renames.append((old_file, target_file))
                        # Track extension changes
                        old_ext = Path(old_file).suffix.lower()
                        new_ext = Path(target_file).suffix.lower()
                        if old_ext != new_ext:
                            pf.extension_changes[new_ext] += 1
                
                # Honeypot check
                target_lower = target_file.lower()
                for honeypot_dir in self.honeypot_dirs:
                    if honeypot_dir.lower() in target_lower:
                        pf.honeypot_accesses += 1
                        break
            
            # Entropy
            entropy = event.get("entropy") or event.get("file_entropy")
            if entropy is not None:
                try:
                    pf.file_entropy_samples.append(float(entropy))
                except (ValueError, TypeError):
                    pass
            
            # Bytes written (if available)
            bytes_written = event.get("bytes_written") or event.get("BytesWritten")
            if bytes_written:
                try:
                    pf.total_bytes_written += int(bytes_written)
                except (ValueError, TypeError):
                    pass
            
            # Network connections with lifecycle tracking
            if "NETWORK" in str(event.get("type", "")).upper() or event.get("EventID") == 3:
                conn_info = {
                    "destination_ip": event.get("DestinationIp") or event.get("destination_ip") or "",
                    "destination_port": event.get("DestinationPort") or event.get("destination_port") or 0,
                    "protocol": event.get("Protocol") or event.get("protocol") or ""
                }
                pf.network_connections.append(conn_info)
                # CRITICAL FIX: Track network connection timestamps for burst detection
                pf.lifecycle_network_conns.append(current_time)
                if conn_info["destination_ip"]:
                    pf.destination_ips.add(conn_info["destination_ip"])
                if conn_info["destination_port"]:
                    pf.ports_touched.add(conn_info["destination_port"])
                pf.sockets_created += 1
                # Lifecycle tracking
                pf.lifecycle_network_conns.append(current_time)
            
            # DNS lookups
            if "DNS" in str(event.get("type", "")).upper():
                dns_query = event.get("QueryName") or event.get("query_name") or ""
                if dns_query:
                    pf.dns_lookups.append(dns_query)
            
            # Registry modifications with lifecycle tracking
            if "REGISTRY" in str(event.get("type", "")).upper() or event.get("EventID") in (12, 13, 14):
                reg_key = event.get("TargetObject") or event.get("target_object") or ""
                if reg_key:
                    pf.registry_modifications.append(reg_key)
                    # Lifecycle tracking
                    pf.lifecycle_registry_mods.append(current_time)
                    # Check for suspicious keys
                    for suspicious_pattern in self.SUSPICIOUS_REGISTRY_KEYS:
                        if re.search(suspicious_pattern, reg_key, re.IGNORECASE):
                            pf.suspicious_registry_keys.add(reg_key)
                            break
            
            # Process creation (child spawning)
            if "PROCESS_CREATE" in str(event.get("type", "")).upper() or event.get("EventID") == 1:
                child_pid = event.get("ProcessId") or event.get("ProcessID")
                if child_pid and child_pid != pf.pid:
                    pf.child_pids.add(child_pid)
                    pf.spawn_count += 1
                
                # Check for suspended creation
                if "suspended" in str(event.get("Message", "")).lower():
                    pf.created_suspended = True
            
            # Module/DLL loading
            if "MODULE" in str(event.get("type", "")).upper() or event.get("EventID") == 7:
                module_path = event.get("ImageLoaded") or event.get("image_loaded") or ""
                if module_path:
                    pf.loaded_modules.add(module_path.lower())
                    # Check for suspicious DLLs
                    module_name = Path(module_path).name.lower()
                    if module_name in self.SUSPICIOUS_DLLS:
                        pf.suspicious_dlls.add(module_path)

            # Process runtime counters (if provided by telemetry)
            thread_count = event.get("ThreadCount") or event.get("thread_count")
            if thread_count is not None:
                try:
                    pf.thread_count_samples.append(float(thread_count))
                except (ValueError, TypeError):
                    pass

            handle_count = event.get("HandleCount") or event.get("handle_count")
            if handle_count is not None:
                try:
                    pf.handle_count_samples.append(float(handle_count))
                except (ValueError, TypeError):
                    pass

            # API-call style telemetry from event payload/message (lightweight keyword matching)
            api_text_parts = [
                event.get("ApiCall"),
                event.get("api_call"),
                event.get("CallTrace"),
                event.get("call_trace"),
                event.get("Message"),
                event.get("CommandLine"),
                event.get("command_line"),
            ]
            api_text = " ".join(str(x) for x in api_text_parts if x).lower()
            if api_text:
                crypt_hits = ["cryptencrypt", "cryptacquirecontext", "bcryptencrypt", "cryptgenkey", "cryptencryptmessage"]
                va_hits = ["virtualalloc", "virtualallocex"]
                wpm_hits = ["writeprocessmemory"]
                crt_hits = ["createremotethread", "createremotethreadex"]

                for token in crypt_hits:
                    if token in api_text:
                        pf.crypt_api_calls += 1
                        pf.api_call_counts["crypt_api"] += 1
                for token in va_hits:
                    if token in api_text:
                        pf.virtualalloc_calls += 1
                        pf.api_call_counts["virtualalloc"] += 1
                for token in wpm_hits:
                    if token in api_text:
                        pf.writeprocessmemory_calls += 1
                        pf.api_call_counts["writeprocessmemory"] += 1
                        if float(event.get("bytes_written") or event.get("BytesWritten") or 0.0) >= 65536.0:
                            pf.large_writeprocessmemory += 1
                for token in crt_hits:
                    if token in api_text:
                        pf.createremotethread_calls += 1
                        pf.api_call_counts["createremotethread"] += 1
            
            # Command line patterns (from Stage 2 reasons)
            reasons = event.get("__reasons", [])
            if "suspicious_powershell_cmdline" in reasons:
                pf.api_call_counts["powershell_suspicious"] += 1
            
            # Update parent chain
            parent_pid = event.get("ParentProcessId") or event.get("parent_process_id")
            if parent_pid and parent_pid not in pf.parent_chain:
                pf.parent_chain.append(parent_pid)
            
        except Exception:
            logger.exception(f"Error updating features for PID {pf.pid}")
    
    def _get_cross_pid_features(self, pid: int, pf: ProcessFeatures, now: float) -> Dict[str, float]:
        """Calculate cross-PID features (parent-child, sibling aggregation)"""
        cross_features = {
            'family_file_creates': 0.0,
            'family_file_deletes': 0.0,
            'family_network_conns': 0.0,
            'family_registry_mods': 0.0,
            'sibling_count': 0.0,
            'family_entropy_avg': 0.0,
            'family_suspicious_paths': 0.0,
        }
        
        # CRITICAL FIX: Include the current process itself in family aggregation
        family_entropies = []
        family_file_creates = len(pf.files_created)  # Start with own files
        family_file_deletes = len(pf.files_deleted)  # Start with own deletes
        family_network = len(pf.network_connections)  # Start with own connections
        family_registry = len(pf.registry_modifications)  # Start with own registry
        suspicious_paths = 1 if self._is_path_anomalous(pf.image_path) else 0
        
        if pf.file_entropy_samples:
            family_entropies.extend(list(pf.file_entropy_samples))
        
        # Aggregate from parent (if exists)
        if pf.parent_chain:
            parent_pid = pf.parent_chain[0]  # Direct parent
            if parent_pid in self.processes:
                parent_pf = self.processes[parent_pid]
                family_file_creates += len(parent_pf.files_created)
                family_file_deletes += len(parent_pf.files_deleted)
                family_network += len(parent_pf.network_connections)
                family_registry += len(parent_pf.registry_modifications)
                if parent_pf.file_entropy_samples:
                    family_entropies.extend(list(parent_pf.file_entropy_samples))
                if self._is_path_anomalous(parent_pf.image_path):
                    suspicious_paths += 1
        
        # Aggregate from siblings (same parent)
        siblings = self.temporal_siblings.get(pid, [])
        cross_features['sibling_count'] = float(len(siblings))
        for sibling_info in siblings:
            sibling_pid = sibling_info[0] if isinstance(sibling_info, tuple) else sibling_info
            if sibling_pid in self.processes:
                sibling_pf = self.processes[sibling_pid]
                family_file_creates += len(sibling_pf.files_created)
                family_file_deletes += len(sibling_pf.files_deleted)
                family_network += len(sibling_pf.network_connections)
                family_registry += len(sibling_pf.registry_modifications)
                if sibling_pf.file_entropy_samples:
                    family_entropies.extend(list(sibling_pf.file_entropy_samples))
                if self._is_path_anomalous(sibling_pf.image_path):
                    suspicious_paths += 1
        
        # Aggregate from children
        children = self.parent_to_children.get(pid, set())
        for child_pid in children:
            if child_pid in self.processes:
                child_pf = self.processes[child_pid]
                family_file_creates += len(child_pf.files_created)
                family_file_deletes += len(child_pf.files_deleted)
                family_network += len(child_pf.network_connections)
                family_registry += len(child_pf.registry_modifications)
                if child_pf.file_entropy_samples:
                    family_entropies.extend(list(child_pf.file_entropy_samples))
                if self._is_path_anomalous(child_pf.image_path):
                    suspicious_paths += 1
        
        cross_features['family_file_creates'] = float(family_file_creates)
        cross_features['family_file_deletes'] = float(family_file_deletes)
        cross_features['family_network_conns'] = float(family_network)
        cross_features['family_registry_mods'] = float(family_registry)
        if family_entropies:
            cross_features['family_entropy_avg'] = sum(family_entropies) / len(family_entropies)
        cross_features['family_suspicious_paths'] = float(suspicious_paths)
        
        return cross_features
    
    def _calculate_sliding_window_rates(self, pf: ProcessFeatures, now: float) -> Dict[str, float]:
        """Calculate file I/O rates using multiple sliding windows"""
        rates = {
            'burstiness_file_io': 0.0,  # Short window (30s)
            'medium_term_file_rate': 0.0,  # Medium window (5min)
            'long_term_file_rate': 0.0,  # Long window (30min)
            'file_io_acceleration': 0.0,  # Rate change
        }
        
        # Short window (30 seconds)
        short_window_writes = [ts for ts in pf.short_window_writes if (now - ts) <= self.short_window_sec]
        if short_window_writes:
            rates['burstiness_file_io'] = len(short_window_writes) / self.short_window_sec
        
        # Medium window (5 minutes)
        medium_window_writes = [ts for ts in pf.medium_window_writes if (now - ts) <= self.medium_window_sec]
        if medium_window_writes:
            rates['medium_term_file_rate'] = len(medium_window_writes) / self.medium_window_sec
        
        # Long window (30 minutes)
        long_window_writes = [ts for ts in pf.long_window_writes if (now - ts) <= self.long_window_sec]
        if long_window_writes:
            rates['long_term_file_rate'] = len(long_window_writes) / self.long_window_sec
        
        # Acceleration (change in rate)
        if rates['medium_term_file_rate'] > 0 and rates['long_term_file_rate'] > 0:
            rates['file_io_acceleration'] = rates['medium_term_file_rate'] / max(rates['long_term_file_rate'], 0.1)
        
        return rates
    
    def _normalize_by_age(self, value: float, age_sec: float, event_count: int) -> float:
        """Normalize feature values by process age and event count for sparse event handling"""
        if age_sec < 0.1:
            age_sec = 0.1  # Avoid division by zero
        
        # Rate per second
        rate = value / age_sec
        
        # If we have very few events, apply interpolation
        if event_count < 5:
            # Interpolate: assume more events would come if process lives longer
            # Scale by expected event rate for typical processes
            expected_rate_multiplier = 1.0 + (5 - event_count) * 0.1
            rate *= expected_rate_multiplier
        
        return rate
    
    def extract_feature_vector(self, pid: int, allow_new_process: bool = False) -> Optional[Dict[str, float]]:
        """
        Extract complete feature vector for a PID with lifecycle aggregation, cross-PID features,
        sliding window metrics, and better sparse event handling.
        
        Args:
            pid: Process ID to extract features for
            allow_new_process: If True, allow feature extraction even for very new processes.
        """
        with self._lock:
            if pid not in self.processes:
                return None
            
            pf = self.processes[pid]
            now = time.time()
            age_sec = now - pf.start_time
            
            # Longer minimum age requirement (was 1 second, now 5 seconds for better aggregation)
            # But allow override for manual promotions
            if not allow_new_process and age_sec < 5.0 and pf.lifecycle_total_events < 3:
                return None
            
            # Update lifecycle peak rate
            pf.update_peak_file_rate()
            
            features = {}
            
            # ========== LIFECYCLE AGGREGATION ==========
            # Normalize by age for sparse event handling
            event_rate = self._normalize_by_age(float(pf.lifecycle_total_events), age_sec, pf.lifecycle_total_events)
            
            # ========== CPU/RAM Features (Lifecycle-aware) ==========
            if pf.cpu_samples:
                features['cpu_usage_trend'] = sum(pf.cpu_samples) / len(pf.cpu_samples)
                features['cpu_spike_deviation'] = max(pf.cpu_samples) - pf.cpu_baseline if pf.cpu_baseline > 0 else 0.0
            else:
                # Interpolate for sparse data: use process name baseline if available
                process_name = Path(pf.image_path).name.lower() if pf.image_path else ""
                if process_name and process_name in self.process_baselines:
                    baseline = self.process_baselines[process_name]
                    features['cpu_usage_trend'] = baseline.get('avg_cpu', 0.0)
                else:
                    features['cpu_usage_trend'] = 0.0
                features['cpu_spike_deviation'] = 0.0
            
            if pf.ram_samples:
                features['ram_usage_trend'] = sum(pf.ram_samples) / len(pf.ram_samples)
                features['sudden_ram_spikes'] = max(pf.ram_samples) - pf.ram_baseline if pf.ram_baseline > 0 else 0.0
            else:
                process_name = Path(pf.image_path).name.lower() if pf.image_path else ""
                if process_name and process_name in self.process_baselines:
                    baseline = self.process_baselines[process_name]
                    features['ram_usage_trend'] = baseline.get('avg_ram', 0.0)
                else:
                    features['ram_usage_trend'] = 0.0
                features['sudden_ram_spikes'] = 0.0
            
            # ========== Process Metrics ==========
            if pf.thread_count_samples:
                current_threads = pf.thread_count_samples[-1] if pf.thread_count_samples else pf.initial_threads
                features['thread_count_delta'] = current_threads - pf.initial_threads
            else:
                features['thread_count_delta'] = 0.0
            
            if pf.handle_count_samples:
                current_handles = pf.handle_count_samples[-1] if pf.handle_count_samples else pf.initial_handles
                features['handle_count_delta'] = current_handles - pf.initial_handles
            else:
                features['handle_count_delta'] = 0.0
            
            # ========== File I/O Features (Lifecycle + Rate-based) ==========
            # Absolute counts
            features['total_bytes_written'] = float(pf.total_bytes_written)
            features['files_created'] = float(len(pf.files_created))
            features['files_modified'] = float(len(pf.files_modified))
            features['files_deleted'] = float(len(pf.files_deleted))
            
            # Rate-based features (normalized by age for sparse events)
            features['files_created_rate'] = self._normalize_by_age(float(len(pf.files_created)), age_sec, pf.lifecycle_total_events)
            features['files_deleted_rate'] = self._normalize_by_age(float(len(pf.files_deleted)), age_sec, pf.lifecycle_total_events)
            features['bytes_written_rate'] = self._normalize_by_age(float(pf.total_bytes_written), age_sec, pf.lifecycle_total_events)
            
            # Lifecycle peak rate
            features['lifecycle_peak_file_rate'] = pf.lifecycle_peak_file_rate
            
            # Sliding window rates (multiple time windows)
            window_rates = self._calculate_sliding_window_rates(pf, now)
            features.update(window_rates)
            
            # Entropy features (lifecycle-aware)
            if pf.file_entropy_samples:
                features['entropy_trend'] = sum(pf.file_entropy_samples) / len(pf.file_entropy_samples)
                if len(pf.file_entropy_samples) > 1:
                    # Use lifecycle data for velocity
                    features['entropy_velocity'] = pf.file_entropy_samples[-1] - pf.file_entropy_samples[0]
                    # Add entropy acceleration (recent vs older)
                    if len(pf.file_entropy_samples) >= 10:
                        recent_avg = sum(list(pf.file_entropy_samples)[-5:]) / 5
                        older_avg = sum(list(pf.file_entropy_samples)[-10:-5]) / 5
                        features['entropy_acceleration'] = recent_avg - older_avg
                    else:
                        features['entropy_acceleration'] = 0.0
                else:
                    features['entropy_velocity'] = 0.0
                    features['entropy_acceleration'] = 0.0
            else:
                features['entropy_trend'] = 0.0
                features['entropy_velocity'] = 0.0
                features['entropy_acceleration'] = 0.0
            
            # ========== Signature/Trust ==========
            features['signature_trust_level'] = 1.0 if pf.is_microsoft_signed else (0.5 if pf.is_signed else 0.0)
            features['is_microsoft_signed'] = 1.0 if pf.is_microsoft_signed else 0.0
            features['cert_mismatch_tampering'] = 1.0 if pf.cert_mismatch else 0.0
            
            # ========== Process Tree ==========
            features['parent_child_anomaly_score'] = float(len(pf.parent_chain))
            features['unexpected_spawning_patterns'] = float(pf.spawn_count)
            
            # ========== CROSS-PID FEATURES ==========
            cross_pid_features = self._get_cross_pid_features(pid, pf, now)
            features.update(cross_pid_features)
            
            # Family aggregate rates
            if age_sec > 0.1:
                features['family_file_rate'] = cross_pid_features['family_file_creates'] / age_sec
                features['family_network_rate'] = cross_pid_features['family_network_conns'] / age_sec
            
            # ========== Network Features (Rate-based) ==========
            features['network_connections'] = float(len(pf.network_connections))
            features['dns_lookup_count'] = float(len(pf.dns_lookups))
            features['outbound_connection_anomaly'] = 1.0 if len(pf.destination_ips) > 10 else 0.0
            features['total_sockets_created'] = float(pf.sockets_created)
            features['unexpected_ports_touched'] = float(len(pf.ports_touched))
            features['unusual_destination_ip_behavior'] = 1.0 if len(pf.destination_ips) > 5 else 0.0
            
            # Network rate (normalized by age)
            features['network_connection_rate'] = self._normalize_by_age(float(len(pf.network_connections)), age_sec, pf.lifecycle_total_events)
            
            # Lifecycle network patterns
            if pf.lifecycle_network_conns:
                # Network burst detection
                recent_conns = [ts for ts in pf.lifecycle_network_conns if (now - ts) <= 60.0]
                features['network_burst_60s'] = float(len(recent_conns))
            else:
                features['network_burst_60s'] = 0.0
            
            # ========== Path/Working Directory ==========
            features['working_directory_anomaly'] = 1.0 if self._is_path_anomalous(pf.working_directory) else 0.0
            features['executable_path_mismatch'] = 1.0 if self._is_path_anomalous(pf.executable_path) else 0.0
            
            # ========== Memory Features ==========
            features['image_memory_disk_mismatch'] = 1.0 if pf.pe_header_mismatch else 0.0
            features['unsigned_image_mapped'] = 1.0 if pf.unsigned_image_mapped else 0.0
            features['writexecutable_memory_regions'] = float(pf.executable_memory_regions)
            if pf.memory_entropy_samples:
                features['memory_region_entropy_anomalies'] = sum(pf.memory_entropy_samples) / len(pf.memory_entropy_samples)
            else:
                features['memory_region_entropy_anomalies'] = 0.0
            features['thread_start_address_anomalies'] = float(pf.suspicious_thread_starts)
            
            # ========== Module/DLL ==========
            features['module_load_anomaly_score'] = pf.dll_load_anomaly_score
            features['unexpected_dlls_loaded'] = float(len(pf.suspicious_dlls))
            features['dlls_unusual_directories'] = 1.0 if any(not self._is_windows_path(dll) for dll in pf.loaded_modules) else 0.0
            
            # ========== API Calls ==========
            features['suspicious_api_call_frequency'] = float(sum(pf.api_call_counts.values()))
            features['excessive_crypt_apis'] = float(pf.crypt_api_calls)
            features['excessive_virtualalloc'] = float(pf.virtualalloc_calls)
            features['excessive_writeprocessmemory'] = float(pf.writeprocessmemory_calls)
            features['excessive_createremotethread'] = float(pf.createremotethread_calls)
            
            # ========== Privileges ==========
            features['token_privilege_escalation'] = float(pf.privilege_escalations)
            features['unexpected_privilege_acquisition'] = float(len(pf.unexpected_privileges))
            features['access_token_manipulation'] = float(pf.token_manipulations)
            
            # ========== Registry ==========
            features['registry_modification_anomaly'] = float(len(pf.suspicious_registry_keys))
            features['scheduled_task_creation_attempts'] = float(pf.scheduled_task_attempts)
            
            # ========== Process Hollowing/Injection ==========
            features['process_created_suspended'] = 1.0 if pf.created_suspended else 0.0
            features['ntunmapviewofsection_usage'] = float(pf.ntunmapview_calls)
            features['large_writeprocessmemory_activity'] = float(pf.large_writeprocessmemory)
            features['thread_resume_sequence_anomalies'] = float(pf.thread_resume_sequences)
            
            # ========== File Patterns ==========
            features['file_rename_patterns'] = float(len(pf.file_renames))
            features['file_extension_anomaly'] = float(len(pf.extension_changes))
            features['content_rewriting_patterns'] = float(pf.content_rewrite_patterns)
            
            # ========== Honeypot ==========
            features['suspicious_honeypot_access'] = float(pf.honeypot_accesses)
            
            # ========== User Interactivity ==========
            features['user_interactivity_anomaly'] = 1.0 if pf.user_interactivity_anomaly else 0.0
            features['unexpected_gui_access'] = 1.0 if pf.gui_access else 0.0
            features['unexpected_clipboard_access'] = 1.0 if pf.clipboard_access else 0.0
            
            # ========== Temporal Correlation (Extended Windows) ==========
            # Multiple time windows for spike detection
            if pf.spike_timestamps:
                spikes_30s = sum(1 for ts in pf.spike_timestamps if (now - ts) <= 30.0)
                spikes_5min = sum(1 for ts in pf.spike_timestamps if (now - ts) <= 300.0)
                spikes_30min = sum(1 for ts in pf.spike_timestamps if (now - ts) <= 1800.0)
                features['temporal_correlation_spikes'] = float(spikes_30s)  # Backward compat
                features['temporal_spikes_5min'] = float(spikes_5min)
                features['temporal_spikes_30min'] = float(spikes_30min)
            else:
                features['temporal_correlation_spikes'] = 0.0
                features['temporal_spikes_5min'] = 0.0
                features['temporal_spikes_30min'] = 0.0
            
            # Lifecycle event distribution
            if pf.lifecycle_file_creates:
                # Calculate event concentration (variance in inter-event times)
                if len(pf.lifecycle_file_creates) > 1:
                    intervals = []
                    sorted_times = sorted(pf.lifecycle_file_creates)
                    for i in range(1, len(sorted_times)):
                        intervals.append(sorted_times[i] - sorted_times[i-1])
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        if avg_interval > 0:
                            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                            features['file_event_concentration'] = 1.0 / (1.0 + variance)  # Higher = more concentrated/bursty
                        else:
                            features['file_event_concentration'] = 1.0
                    else:
                        features['file_event_concentration'] = 0.0
                else:
                    features['file_event_concentration'] = 0.0
            else:
                features['file_event_concentration'] = 0.0
            
            # ========== Baseline Deviation ==========
            process_name = Path(pf.image_path).name.lower() if pf.image_path else ""
            if process_name and process_name in self.process_baselines:
                baseline = self.process_baselines[process_name]
                if baseline['sample_count'] > 0:
                    cpu_dev = abs(features['cpu_usage_trend'] - baseline['avg_cpu'])
                    ram_dev = abs(features['ram_usage_trend'] - baseline['avg_ram'])
                    features['baseline_deviation_score'] = (cpu_dev + ram_dev) / 2.0
                else:
                    features['baseline_deviation_score'] = 0.0
            else:
                features['baseline_deviation_score'] = 0.0
            
            # ========== YARA (Context-aware) ==========
            # These are set by Stage 3 engine after YARA scan. Default to 0.0 if not set.
            # We intentionally avoid a single binary yara_match flag to reduce false positives
            # and to provide richer signals for ML training.
            features['yara_match_memory'] = 0.0
            features['yara_match_executable'] = 0.0
            features['yara_match_script'] = 0.0
            features['yara_match_document'] = 0.0
            features['yara_match_ads'] = 0.0
            features['yara_weighted_confidence'] = 0.0
            features['yara_match_strength'] = 0.0  # Missing feature - default to 0.0
            
            # ========== MISSING FEATURES (Placeholders for model compatibility) ==========
            # These features were expected by the trained model but not yet implemented.
            # Setting them to 0.0 allows production deployment without errors.
            # TODO: Implement these features for improved detection accuracy
            features['burstiness_file_io'] = 0.0  # File I/O burstiness metric
            features['spawn_depth'] = float(len(pf.parent_chain))  # Process tree depth (already available)
            features['injection_edge_flag'] = 0.0  # Cross-process injection indicator
            features['shared_handles_flag'] = 0.0  # Shared handle detection
            features['beacon_interval_std'] = 0.0  # Network beacon timing analysis
            features['suspicious_tld_flag'] = 0.0  # Suspicious top-level domain detection
            features['asn_risk_score'] = 0.0  # ASN risk scoring (requires external API)
            features['geo_risk_score'] = 0.0  # Geographic risk scoring (requires external API)
            
            # Ensure all features have default values (for sparse events)
            # Set missing optional features to 0.0 if not already present
            optional_features = {
                'files_created_rate', 'files_deleted_rate', 'bytes_written_rate',
                'lifecycle_peak_file_rate', 'medium_term_file_rate', 'long_term_file_rate',
                'file_io_acceleration', 'entropy_acceleration',
                'family_file_creates', 'family_file_deletes', 'family_network_conns',
                'family_registry_mods', 'sibling_count', 'family_entropy_avg',
                'family_suspicious_paths', 'family_file_rate', 'family_network_rate',
                'network_connection_rate', 'network_burst_60s',
                'temporal_spikes_5min', 'temporal_spikes_30min', 'file_event_concentration',
            }
            for feat_name in optional_features:
                if feat_name not in features:
                    features[feat_name] = 0.0
            
            return features
    
    def get_feature_diagnostics(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Get diagnostics about feature extraction for a PID.
        Returns None if PID not found.
        """
        with self._lock:
            if pid not in self.processes:
                return None
            
            pf = self.processes[pid]
            now = time.time()
            age_sec = now - pf.start_time
            
            # Determine data quality
            has_process_create = "PROCESS_CREATE" in pf.event_types_seen or "EventID_1" in pf.event_types_seen
            has_file_events = "FILE_CREATE" in pf.event_types_seen or "EventID_11" in pf.event_types_seen
            has_network_events = "NETWORK_CONNECT" in pf.event_types_seen or "EventID_3" in pf.event_types_seen
            has_registry_events = any("REGISTRY" in et or "EventID_12" in et or "EventID_13" in et or "EventID_14" in et 
                                     for et in pf.event_types_seen)
            
            # Count non-zero features (approximate)
            non_zero_features = sum([
                1 if len(pf.files_modified) > 0 else 0,
                1 if len(pf.network_connections) > 0 else 0,
                1 if len(pf.registry_modifications) > 0 else 0,
                1 if pf.total_bytes_written > 0 else 0,
                1 if len(pf.file_entropy_samples) > 0 else 0,
            ])
            
            # Enhanced quality determination with more granular levels
            if has_process_create and (has_file_events or has_network_events or has_registry_events) and non_zero_features >= 5:
                data_quality = "excellent"
            elif has_process_create and (has_file_events or has_network_events or has_registry_events) and non_zero_features >= 3:
                data_quality = "good"
            elif has_process_create and (has_file_events or has_network_events):
                data_quality = "partial"
            elif len(pf.event_types_seen) >= 3 and pf.event_count >= 3:
                data_quality = "minimal"
            elif len(pf.event_types_seen) > 0:
                data_quality = "insufficient"
            else:
                data_quality = "none"
            
            # Identify missing critical event types
            missing_critical = []
            if not has_process_create:
                missing_critical.append("PROCESS_CREATE (EventID 1)")
            if not has_file_events and data_quality != "complete":
                missing_critical.append("FILE_CREATE (EventID 11)")
            if not has_network_events and "NETWORK_CONNECT" not in str(pf.event_types_seen):
                # Network is optional, only add if we have no network data but process is network-related
                pass
            
            # Calculate feature coverage percentage
            expected_feature_categories = 12  # Approximate categories
            feature_coverage_pct = (non_zero_features / max(expected_feature_categories, 1)) * 100
            
            # Additional diagnostic metrics
            file_ops_count = len(pf.files_created) + len(pf.files_modified) + len(pf.files_deleted)
            network_connections_count = len(pf.network_connections)
            registry_mods_count = len(pf.registry_modifications)
            
            return {
                "events_seen": pf.event_count,
                "event_types_seen": sorted(list(pf.event_types_seen)),
                "time_window_sec": round(age_sec, 3),
                "data_quality": data_quality,
                "missing_critical_events": missing_critical,
                "has_process_create": has_process_create,
                "has_file_events": has_file_events,
                "has_network_events": has_network_events,
                "has_registry_events": has_registry_events,
                "non_zero_feature_count": non_zero_features,
                "feature_coverage_pct": round(feature_coverage_pct, 1),
                "file_operations_count": file_ops_count,
                "network_connections_count": network_connections_count,
                "registry_modifications_count": registry_mods_count,
                "process_age_sec": round(age_sec, 2),
                "image_path": pf.image_path,
                "command_line": pf.command_line[:200] if pf.command_line else "",  # Truncate long command lines
                "files_modified_count": len(pf.files_modified),
                "network_connections_count": len(pf.network_connections),
                "registry_modifications_count": len(pf.registry_modifications),
            }
    
    def _is_path_anomalous(self, path: str) -> bool:
        """Check if path is anomalous (system process from user folder, etc.)"""
        if not path:
            return False
        path_lower = path.lower()
        # System processes should not run from user folders
        user_folders = ['\\users\\', '\\appdata\\', '\\temp\\']
        if any(user_folder in path_lower for user_folder in user_folders):
            return True
        return False
    
    def _is_windows_path(self, path: str) -> bool:
        """Check if path is in known Windows directories"""
        if not path:
            return False
        path_lower = path.lower()
        return any(win_path.lower() in path_lower for win_path in self.WINDOWS_PATHS)
    
    def _cleanup_worker(self) -> None:
        """Background thread worker for periodic cleanup"""
        while not self._cleanup_stop_event.wait(self._cleanup_interval_sec):
            try:
                self.cleanup_old_processes()
            except Exception:
                logger.exception("Error in cleanup worker thread")
    
    def start_cleanup_thread(self) -> None:
        """Start background cleanup thread"""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        self._cleanup_stop_event.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_worker,
            daemon=True,
            name="FeatureExtractorCleanup"
        )
        self._cleanup_thread.start()
        logger.debug("FeatureExtractor cleanup thread started")
    
    def stop_cleanup_thread(self) -> None:
        """Stop background cleanup thread"""
        if self._cleanup_thread:
            self._cleanup_stop_event.set()
            self._cleanup_thread.join(timeout=5.0)
            self._cleanup_thread = None
            logger.debug("FeatureExtractor cleanup thread stopped")
    
    def cleanup_old_processes(self) -> None:
        """Remove processes older than cleanup_sec and clean up cross-PID tracking"""
        with self._lock:
            now = time.time()
            to_remove = [
                pid for pid, pf in self.processes.items()
                if (now - pf.last_update) > self.cleanup_sec
            ]
            for pid in to_remove:
                # Clean up cross-PID tracking
                if pid in self.pid_to_process:
                    del self.pid_to_process[pid]
                
                # Remove from parent_to_children
                for parent_pid, children in list(self.parent_to_children.items()):
                    children.discard(pid)
                    if not children:
                        del self.parent_to_children[parent_pid]
                
                # Remove from temporal_siblings
                if pid in self.temporal_siblings:
                    del self.temporal_siblings[pid]
                # Remove references to this PID from other siblings
                for other_pid, siblings in list(self.temporal_siblings.items()):
                    self.temporal_siblings[other_pid] = [(sib_pid, delta) for sib_pid, delta in siblings if sib_pid != pid]
                
                # Remove from processes dict
                del self.processes[pid]
            
            if to_remove:
                logger.debug(f"Cleaned up {len(to_remove)} old processes and cross-PID references")
            self._last_cleanup_time = now
    
    def get_process_count(self) -> int:
        """Get current number of tracked processes"""
        with self._lock:
            return len(self.processes)

