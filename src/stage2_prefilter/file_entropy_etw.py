# src/stage2_prefilter/file_entropy_etw.py
"""
REAL-TIME FILE CONTENT ENTROPY + MAGIC HEADER ANALYSIS (production-ready)

- Uses Kernel-File ETW provider to sample files on-write for entropy / magic header checks.
- Fixed ETW subscribe signature for pywin32 variations.
- Uses an asyncio event loop dedicated to sampling I/O to avoid blocking the main thread.
- Integrates with your existing Prefilter engine via direct reference to `_ENGINE`.
"""

import asyncio
import threading
import os
import time
import logging
import math
from typing import Optional, Dict, Any
from collections import defaultdict

logger = logging.getLogger("file_entropy_etw")
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[ENTROPY] %(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)

# Tunables
ENABLED = True
SAMPLE_SIZE = 64 * 1024        # 64 KB
MIN_FILE_SIZE = 2 * 1024       # skip tiny files
DEBOUNCE_SEC = 0.45
MAX_FILES_PER_SEC = 300
CLEANUP_INTERVAL = 60

# Magic signatures used for quick checks
MAGIC_SIGNATURES = {
    b'\x50\x4B\x03\x04': "ZIP/OFFICE",
    b'\x50\x4B\x05\x06': "EMPTY_ZIP_TRICK",
    b'\x50\x4B\x07\x08': "SPANNED_ZIP",
    b'\x25\x50\x44\x46': "PDF",
    b'\xD0\xCF\x11\xE0': "OLE2",
    b'\x7F\x45\x4C\x46': "ELF",
    b'\x4D\x5A': "PE_EXE_DLL",
    b'\xFF\xD8\xFF': "JPEG",
    b'\x89PNG\r\n\x1a\n': "PNG",
    b'Rar!\x1a\x07': "RAR",
    b'\x1F\x8B': "GZIP",
}

# Protect global state
_last_sampled: Dict[str, float] = {}
_sample_counter = 0
_counter_lock = threading.Lock()

# Import pywin32 pieces (fail gracefully if missing)
try:
    import win32evtlog
    import win32event
    import xml.etree.ElementTree as ET
    _HAS_WIN32 = True
except Exception:
    logger.critical("pywin32 is missing. Install: pip install pywin32")
    _HAS_WIN32 = False

# Import Prefilter engine's global _ENGINE safely (non-fatal if not present)
try:
    from stage2_prefilter.prefilter_engine import _ENGINE  # type: ignore
except Exception:
    _ENGINE = None
    logger.warning("Prefilter engine _ENGINE not found on import; entropy will still compute but not push promotions")


def shannon_entropy(data: bytes) -> float:
    if not data or len(data) < 256:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    inv_len = 1.0 / len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c * inv_len
            ent -= p * math.log2(p)
    return round(ent, 4)


def detect_magic_header(data: bytes) -> Optional[str]:
    if not data:
        return None
    for sig, name in MAGIC_SIGNATURES.items():
        if data.startswith(sig):
            return name
    if len(data) >= 128:
        # No known signature in the first 128 bytes — suspicious when expecting common formats
        return "NO_KNOWN_HEADER"
    return None


async def sample_file_async(filepath: str, pid: int):
    """
    Non-blocking file read via an executor to compute entropy + detect magic.
    Updates _ENGINE.tracker if available.
    """
    global _sample_counter
    now = time.monotonic()

    with _counter_lock:
        if _sample_counter >= MAX_FILES_PER_SEC:
            return
        last = _last_sampled.get(filepath, 0)
        if now - last < DEBOUNCE_SEC:
            return
        _last_sampled[filepath] = now
        _sample_counter += 1

    try:
        loop = asyncio.get_running_loop()
        # Read SAMPLE_SIZE bytes in threadpool (safe, non-blocking for asyncio)
        data = await loop.run_in_executor(None, lambda: open(filepath, "rb").read(SAMPLE_SIZE))
    except (PermissionError, FileNotFoundError, OSError):
        return
    except Exception as e:
        logger.debug("sample read failed: %s", e)
        return

    try:
        if len(data) < MIN_FILE_SIZE:
            return

        ent = shannon_entropy(data)
        magic = detect_magic_header(data)

        # Feed the engine tracker (if present)
        try:
            if _ENGINE is not None and hasattr(_ENGINE, "tracker"):
                _ENGINE.tracker.update_entropy(pid, ent)
        except Exception:
            logger.debug("Failed to push entropy sample into engine tracker", exc_info=True)

        # Decide suspicious reasons (only logging here; promotion happens in engine)
        reasons = []
        if ent >= 7.85:
            reasons.append(f"high_entropy={ent:.3f}")
        if magic == "NO_KNOWN_HEADER":
            reasons.append("no_known_header")
        if magic == "EMPTY_ZIP_TRICK":
            reasons.append("empty_zip_trick")

        if reasons:
            logger.warning("ENTROPY ALERT pid=%s ent=%.3f magic=%s file=%s reasons=%s", pid, ent, magic or "None", filepath, ", ".join(reasons))

    finally:
        # decrement sample counter eventually in a separate cleanup loop
        pass


def _cleanup_counters():
    global _sample_counter
    while True:
        time.sleep(CLEANUP_INTERVAL)
        with _counter_lock:
            now = time.monotonic()
            expired = [p for p, t in _last_sampled.items() if now - t > 300]
            for p in expired:
                _last_sampled.pop(p, None)
            _sample_counter = 0


def start_entropy_etw():
    """
    Start a background thread that subscribes to Kernel-File ETW provider and triggers async sampling.
    Uses a dedicated asyncio loop inside the thread to schedule sampling tasks.
    Safe for multiple imports (idempotent).
    """
    if not ENABLED:
        logger.info("File entropy: disabled by configuration")
        return
    if not _HAS_WIN32:
        logger.critical("File entropy: pywin32 not available")
        return

    def etw_thread_main():
        # dedicated loop for sampling tasks
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # start cleanup task in background thread pool (not critical)
        loop.run_in_executor(None, _cleanup_counters)

        query = """
        <QueryList>
          <Query Id="0" Path="Microsoft-Windows-Kernel-File">
            <Select Path="Microsoft-Windows-Kernel-File">
              *[System[(EventID=2 or EventID=11)]] and
              *[EventData/Data[@Name='FileName']] and
              *[EventData/Data[@Name='ProcessID']]
            </Select>
          </Query>
        </QueryList>
        """

        sub_handle = None
        try:
            # Best-effort safe subscription: EvtSubscribe(Session=0, SignalEvent=0, ChannelPath, Query, Bookmark=0, Context=0, Flags)
            # Passing integer 0 for signal handles avoids PyHANDLE issues in some pywin32 versions.
            EvtSubscribeToFuture = getattr(win32evtlog, "EvtSubscribeToFutureEvents", 1)
            sub_handle = win32evtlog.EvtSubscribe(
                0,
                0,
                "Microsoft-Windows-Kernel-File",
                query,
                0,
                0,
                EvtSubscribeToFuture,
            )
            logger.info("Kernel-File ETW subscription started")
        except Exception as exc:
            logger.critical("Failed to subscribe to Kernel-File ETW: %s", exc)
            # close loop cleanly
            try:
                loop.stop()
            except Exception:
                pass
            return

        try:
            while True:
                try:
                    # wait up to 2 seconds for events; EvtNext returns a list or raises
                    events = win32evtlog.EvtNext(sub_handle, 50, 2000)
                    if not events:
                        continue
                    for evt in events:
                        try:
                            xml = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
                            root = ET.fromstring(xml)

                            pid_el = root.find(".//Data[@Name='ProcessID']")
                            fname_el = root.find(".//Data[@Name='FileName']")
                            if not fname_el or not fname_el.text:
                                continue
                            pid = int(pid_el.text) if (pid_el is not None and pid_el.text) else 0
                            filepath = fname_el.text.strip()
                            # normalize file path, skip relative or inaccessible files
                            if not os.path.isabs(filepath) or not os.path.exists(filepath):
                                continue

                            low = filepath.lower()
                            # skip temp/log files to reduce noise
                            if any(low.endswith(ext) for ext in ('.tmp', '.temp', '.log', '.ldb', '.cache', '.evt', '.evtx')):
                                continue
                            if '\\temp\\' in low or '\\appdata\\local\\temp\\' in low:
                                continue

                            # schedule sampling on the dedicated loop (thread-safe)
                            asyncio.run_coroutine_threadsafe(sample_file_async(filepath, pid), loop)

                        except Exception:
                            # individual event parse shouldn't break the loop
                            logger.debug("ETW event parse error", exc_info=True)
                except Exception as e:
                    # tolerate transient RPC errors
                    if "RPC_S_INVALID_BOUND" in str(e):
                        time.sleep(0.1)
                        continue
                    logger.error("ETW EvtNext failure: %s", e)
                    time.sleep(1)
        finally:
            try:
                if sub_handle:
                    win32evtlog.EvtClose(sub_handle)
            except Exception:
                pass
            try:
                loop.stop()
            except Exception:
                pass

    t = threading.Thread(target=etw_thread_main, name="ETW-FileEntropy", daemon=True)
    t.start()
    logger.info("File entropy background thread launched")


# Auto-start only when module imported and enabled
if ENABLED and _HAS_WIN32:
    try:
        start_entropy_etw()
    except Exception as e:
        logger.critical("Failed to start file entropy collector: %s", e)
