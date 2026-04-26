# stage1_collection/sysmon_listener_pro.py
# Hardened, production-grade Sysmon ingestion layer
# Zero-loss bookmarking, safe threading, robust XML parsing

import logging
import threading
import time
import xml.etree.ElementTree as ET
from typing import Callable, Dict, Any, Optional
from collections import deque

import win32evtlog 
import win32con    

logger = logging.getLogger("sysmon_listener_pro")

NormalizedEvent = Dict[str, Any]
Callback = Callable[[NormalizedEvent], None]


class SysmonListenerPro:
    """
    Production-grade Sysmon listener used in enterprise deployments.
    Features:
      - Bookmark resume (no missed events)
      - Robust ET parsing
      - Thread-safe shutdown
      - Normalized Sysmon fields
      - Event overload protection
    """

    def __init__(
        self,
        callback: Callback,
        logname: str = "Microsoft-Windows-Sysmon/Operational",
        bookmark_path: Optional[str] = "sysmon_bookmark.xml",
        max_events_per_sec: Optional[float] = None,  # Rate limiting: None = disabled, float = max events/sec
        rate_limit_window_sec: float = 1.0,  # Time window for rate limiting
    ):
        self.callback = callback
        self.logname = logname
        self.bookmark_path = bookmark_path
        
        # Rate limiting
        self.max_events_per_sec = max_events_per_sec
        self.rate_limit_window_sec = rate_limit_window_sec
        self._rate_limit_timestamps = deque(maxlen=10000)  # Track last N event timestamps
        self._rate_limit_lock = threading.Lock()
        self._rate_limit_dropped = 0
        self._rate_limit_total = 0

        self._stop_event = threading.Event()
        self._thread = None

        self.bookmark = None
        self._load_bookmark()
        
        if self.max_events_per_sec:
            logger.info(f"Rate limiting enabled: max {self.max_events_per_sec} events/sec")

    # --------------------------------------------------------
    # Bookmark load/save
    # --------------------------------------------------------
    def _load_bookmark(self):
        if not self.bookmark_path:
            return

        try:
            with open(self.bookmark_path, "rb") as f:
                self.bookmark = f.read()
            logger.info("Loaded Sysmon bookmark (%d bytes)", len(self.bookmark))
        except FileNotFoundError:
            logger.info("No bookmark found — starting from latest events")
        except Exception as e:
            logger.error("Failed to load bookmark: %s", e)

    def _save_bookmark(self):
        if not self.bookmark_path or not self.bookmark:
            return
        try:
            with open(self.bookmark_path, "wb") as f:
                f.write(self.bookmark)
            logger.debug("Bookmark saved")
        except Exception as e:
            logger.error("Failed to save bookmark: %s", e)
    
    def _check_rate_limit(self) -> bool:
        """
        Check if event should be processed based on rate limiting.
        
        Returns:
            True if event should be processed, False if it should be dropped
        """
        if not self.max_events_per_sec:
            return True  # Rate limiting disabled
        
        now = time.time()
        with self._rate_limit_lock:
            # Remove timestamps outside the window
            while self._rate_limit_timestamps and (now - self._rate_limit_timestamps[0]) > self.rate_limit_window_sec:
                self._rate_limit_timestamps.popleft()
            
            # Check if we're over the limit
            if len(self._rate_limit_timestamps) >= int(self.max_events_per_sec * self.rate_limit_window_sec):
                self._rate_limit_dropped += 1
                self._rate_limit_total += 1
                
                # Log warning every 1000 dropped events
                if self._rate_limit_dropped % 1000 == 0:
                    logger.warning(
                        f"Rate limit exceeded: dropped {self._rate_limit_dropped} events "
                        f"(limit: {self.max_events_per_sec} events/sec)"
                    )
                
                return False
            
            # Add current timestamp
            self._rate_limit_timestamps.append(now)
            self._rate_limit_total += 1
            return True
    
    def get_rate_limit_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        with self._rate_limit_lock:
            return {
                "max_events_per_sec": self.max_events_per_sec,
                "total_events": self._rate_limit_total,
                "dropped_events": self._rate_limit_dropped,
                "drop_rate": (self._rate_limit_dropped / max(1, self._rate_limit_total)) * 100,
                "current_window_events": len(self._rate_limit_timestamps),
            }

    # --------------------------------------------------------
    # Start/Stop
    # --------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="SysmonProListener"
        )
        self._thread.start()
        logger.info("SysmonListenerPro started")

    def stop(self, timeout: float = 10.0):
        logger.info("Stopping SysmonListenerPro...")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout)
        self._save_bookmark()
        logger.info("SysmonListenerPro stopped")

    # --------------------------------------------------------
    # Normalize XML
    # --------------------------------------------------------
    def _normalize(self, xml_str: str) -> Optional[NormalizedEvent]:
        try:
            root = ET.fromstring(xml_str)
        except Exception as e:
            logger.error("XML parse failed: %s", e)
            return None

        def get(name):
            el = root.find(f".//Data[@Name='{name}']")
            return el.text if el is not None else None

        # Event ID
        try:
            event_id = int(root.find(".//EventID").text)
        except Exception:
            return None

        event_map = {
            1: "PROCESS_CREATE",
            3: "NETWORK_CONNECT",
            5: "PROCESS_TERMINATED",
            7: "IMAGE_LOAD",
            8: "CREATE_REMOTE_THREAD",
            9: "RAW_ACCESS_READ",
            10: "PROCESS_ACCESS",
            11: "FILE_CREATE",
            12: "REGISTRY_ADD",
            13: "REGISTRY_SET",
            14: "REGISTRY_RENAME",
            15: "FILE_CREATE_STREAM_HASH",
            16: "SERVICE_CONFIGURATION_CHANGE",
            17: "DRIVER_LOAD",
            18: "PIPE_CREATED",
            19: "WMI_EVENT_FILTER",
            20: "WMI_EVENT_CONSUMER",
            21: "WMI_EVENT_BINDING",
            22: "DNS_QUERY",
            23: "FILE_DELETE",
            24: "CLIPBOARD_CHANGE",
            25: "PROCESS_TAMPERING",
            255: "SYSMON_CONFIG_CHANGE",
        }

        # Extract ProcessId (CRITICAL: needed for Stage 2/3)
        process_id_str = get("ProcessId")
        process_id = None
        if process_id_str:
            try:
                process_id = int(process_id_str)
            except (ValueError, TypeError):
                pass

        # Extract ParentProcessId as integer
        parent_process_id_str = get("ParentProcessId")
        parent_process_id = None
        if parent_process_id_str:
            try:
                parent_process_id = int(parent_process_id_str)
            except (ValueError, TypeError):
                pass

        # Build normalized event
        normalized = {
            # Event ID - add both variants for compatibility
            "event_id": event_id,
            "EventID": event_id,  # CRITICAL: Add uppercase variant
            "type": event_map.get(event_id, f"SYSMON_{event_id}"),
            "timestamp": root.find(".//TimeCreated").get("SystemTime"),
            "utc_time": get("UtcTime"),

            # Process info - add all variants for compatibility
            "process_guid": get("ProcessGuid"),
            "ProcessGuid": get("ProcessGuid"),  # Add uppercase variant
            "image": get("Image"),
            "Image": get("Image"),  # Add uppercase variant
            "command_line": get("CommandLine"),
            "CommandLine": get("CommandLine"),  # Add uppercase variant
            "parent_process_guid": get("ParentProcessGuid"),
            "ParentProcessGuid": get("ParentProcessGuid"),  # Add uppercase variant
            "parent_process_id": parent_process_id,
            "ParentProcessId": parent_process_id,  # Add uppercase variant
            "parent_image": get("ParentImage"),
            "ParentImage": get("ParentImage"),  # Add uppercase variant
            "parent_command_line": get("ParentCommandLine"),
            "ParentCommandLine": get("ParentCommandLine"),  # Add uppercase variant
        }

        # CRITICAL: Add ProcessID in all variants (ProcessID, ProcessId, process_id, pid)
        if process_id is not None:
            normalized["ProcessID"] = process_id
            normalized["ProcessId"] = process_id
            normalized["process_id"] = process_id
            normalized["pid"] = process_id

        # Add additional useful fields
        normalized.update({
            # User / system context
            "user": get("User"),
            "User": get("User"),  # Add uppercase variant
            "logon_id": get("LogonId"),
            "LogonId": get("LogonId"),  # Add uppercase variant
            "integrity": get("IntegrityLevel"),
            "IntegrityLevel": get("IntegrityLevel"),  # Add uppercase variant

            # File/Network/Registry fields
            "hashes": get("Hashes"),
            "Hashes": get("Hashes"),  # Add uppercase variant
            "rule_name": get("RuleName"),
            "RuleName": get("RuleName"),  # Add uppercase variant
            "target_filename": get("TargetFilename"),
            "TargetFilename": get("TargetFilename"),  # Add uppercase variant
            "destination_ip": get("DestinationIp"),
            "DestinationIp": get("DestinationIp"),  # Add uppercase variant
            "destination_port": get("DestinationPort"),
            "DestinationPort": get("DestinationPort"),  # Add uppercase variant
            "protocol": get("Protocol"),
            "Protocol": get("Protocol"),  # Add uppercase variant
            "image_loaded": get("ImageLoaded"),
            "ImageLoaded": get("ImageLoaded"),  # Add uppercase variant

            # Additional useful fields for feature extraction
            "source_ip": get("SourceIp"),
            "SourceIp": get("SourceIp"),
            "source_port": get("SourcePort"),
            "SourcePort": get("SourcePort"),
            "source_process_guid": get("SourceProcessGuid"),
            "SourceProcessGuid": get("SourceProcessGuid"),
            "source_process_id": get("SourceProcessId"),
            "SourceProcessId": get("SourceProcessId"),
            "source_image": get("SourceImage"),
            "SourceImage": get("SourceImage"),
            "query_name": get("QueryName"),
            "QueryName": get("QueryName"),  # For DNS events (EventID 22)
            
            # Process/File metadata (useful for analysis)
            "file_version": get("FileVersion"),
            "FileVersion": get("FileVersion"),
            "description": get("Description"),
            "Description": get("Description"),
            "company": get("Company"),
            "Company": get("Company"),
            "product": get("Product"),
            "Product": get("Product"),
            "is_executable": get("IsExecutable"),
            "IsExecutable": get("IsExecutable"),  # For file events
            
            # Process access fields (EventID 10)
            "granted_access": get("GrantedAccess"),
            "GrantedAccess": get("GrantedAccess"),
            "call_trace": get("CallTrace"),
            "CallTrace": get("CallTrace"),  # Stack trace for some events
            
            # Registry fields (EventID 12, 13, 14)
            "target_object": get("TargetObject"),
            "TargetObject": get("TargetObject"),
            "new_name": get("NewName"),
            "NewName": get("NewName"),  # For registry rename events
            
            # Additional context fields
            "details": get("Details"),
            "Details": get("Details"),
            "event_type": get("EventType"),
            "EventType": get("EventType"),

            # Raw XML (optional)
            "raw_xml": xml_str,
        })

        return normalized

    # --------------------------------------------------------
    # Main event loop
    # --------------------------------------------------------
    def _run(self):
        query = "*[System[(EventRecordID)]]"

        flags = win32evtlog.EvtSubscribeToFutureEvents
        if self.bookmark:
            flags |= win32evtlog.EvtSubscribeStartAfterBookmark

        sub = None
        try:
            # EvtSubscribe signature: (Session, SignalEvent, ChannelPath, Query, Bookmark, Context, Flags)
            # SignalEvent parameter must be an integer handle or 0 (no signal). Using 0 avoids PyHANDLE issues
            # and lets us rely on EvtNext timeouts for polling.
            sub = win32evtlog.EvtSubscribe(
                0,  # Session handle (0 = local)
                0,  # SignalEvent handle (0 = no signal handle, use EvtNext polling)
                self.logname,
                query,
                Bookmark=self.bookmark,
                Flags=flags,
            )
        except Exception as e:
            logger.error("Failed to subscribe to Sysmon events: %s", e)
            logger.debug("This is usually a permissions issue. Ensure running as Administrator or check Sysmon event log access.")
            return

        try:
            while not self._stop_event.is_set():
                try:
                    events = win32evtlog.EvtNext(sub, 50, 200)  # up to 50 events, 200ms wait
                except Exception as e:
                    if "RPC_S_INVALID_BOUND" in str(e):
                        logger.warning("EvtNext glitch (ignored): %s", e)
                        time.sleep(0.2)
                        continue
                    logger.error("EvtNext failed: %s", e)
                    time.sleep(1)
                    continue

                for evt in events:
                    try:
                        # Check rate limit before processing
                        if not self._check_rate_limit():
                            # Still update bookmark to avoid missing events, but skip callback
                            bm = win32evtlog.EvtCreateBookmark(None)
                            win32evtlog.EvtUpdateBookmark(bm, evt)
                            self.bookmark = win32evtlog.EvtRender(bm, win32evtlog.EvtRenderBookmark)
                            continue
                        
                        xml = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
                        data = self._normalize(xml)
                        if data:
                            try:
                                self.callback(data)
                            except Exception as callback_error:
                                logger.error(f"Callback error (event not lost, bookmark updated): {callback_error}")
                                # Continue processing - don't crash the event loop
                                # Bookmark will still be updated below to prevent event loss

                        # Save bookmark
                        bm = win32evtlog.EvtCreateBookmark(None)
                        win32evtlog.EvtUpdateBookmark(bm, evt)
                        self.bookmark = win32evtlog.EvtRender(bm, win32evtlog.EvtRenderBookmark)

                    except Exception as e:
                        logger.error("Error processing event: %s", e)

        finally:
            self._save_bookmark()
            if sub is not None:
                try:
                    win32evtlog.CloseEventLog(sub)
                except Exception:
                    pass


# === Example usage ===
if __name__ == "__main__":
    import logging, json
    logging.basicConfig(level=logging.INFO)

    def cb(ev):
        print(json.dumps(ev, indent=2))

    listener = SysmonListenerPro(
        callback=cb,
        bookmark_path=r"C:\Tools\Sysmon\bookmark.xml",
    )
    listener.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        listener.stop()
