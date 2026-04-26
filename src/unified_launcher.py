#!/usr/bin/env python3
"""
src/unified_launcher.py — production-ready launcher with robust NxLog TCP listener.
Preserves Stage-2 promotion behavior and dashboard hooks.
"""

import asyncio
import json
import logging
import signal
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
import random
import uuid
from typing import Optional, Callable, Dict, Any

# Mode configuration (dataset collection vs production)
try:
    from config.mode_config import get_mode_manager, RunMode  # type: ignore
    MODE_MANAGER_AVAILABLE = True
except Exception:
    MODE_MANAGER_AVAILABLE = False

# Central config (optional)
try:
    from config.edr_config import get_config as get_edr_config  # type: ignore
    EDR_CONFIG_AVAILABLE = True
except Exception:
    get_edr_config = None
    EDR_CONFIG_AVAILABLE = False

# UTILS — Event Normalizer
try:
    from utils.event_normalizer import EventNormalizer  # type: ignore
    NORMALIZER_AVAILABLE = True
except Exception as e:
    EventNormalizer = None
    NORMALIZER_AVAILABLE = False
    logging.getLogger("UNIFIED_EDR").debug("Event Normalizer not available: %s", e)

# STAGE 2 — attempt to import the prefilter module and optional _ENGINE reference
PREFILTER_READY = False
try:
    from stage2_prefilter import prefilter_engine as _prefmod  # type: ignore
    # prefer engine object if present
    try:
        _ENGINE = getattr(_prefmod, "_ENGINE", None)
    except Exception:
        _ENGINE = None
    PREFILTER_READY = True
    logging.getLogger("UNIFIED_EDR").info("Stage 2 Prefilter imported")
except Exception as e:
    _prefmod = None
    _ENGINE = None
    logging.getLogger("UNIFIED_EDR").warning("Stage 2 Prefilter not available: %s", e)

# STAGE 3 — Feature Extraction + Fast ML
STAGE3_READY = False
try:
    from stage3_feature_extraction import Stage3Engine, initialize_stage3  # type: ignore
    STAGE3_READY = True
    logging.getLogger("UNIFIED_EDR").info("Stage 3 Feature Extraction + ML imported")
except Exception as e:
    Stage3Engine = None
    initialize_stage3 = None
    logging.getLogger("UNIFIED_EDR").warning("Stage 3 not available: %s", e)

# STAGE 4 — Full Scorer
STAGE4_READY = False
try:
    from stage4_full_scorer import Stage4Engine, initialize_stage4  # type: ignore
    STAGE4_READY = True
    logging.getLogger("UNIFIED_EDR").info("Stage 4 Full Scorer imported")
except Exception as e:
    Stage4Engine = None
    initialize_stage4 = None
    logging.getLogger("UNIFIED_EDR").warning("Stage 4 not available: %s", e)

# Logging - must be set up first (before dashboard import so we can log errors)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("UNIFIED_EDR")

# Suppress Windows asyncio ProactorEventLoop AssertionError spam
# These are non-fatal internal asyncio errors on Windows
class AsyncioErrorFilter(logging.Filter):
    def filter(self, record):
        # Suppress AssertionError from _ProactorBaseWritePipeTransport
        msg = record.getMessage() if hasattr(record, 'getMessage') else str(record.msg)
        
        # Check message content for asyncio-related errors
        asyncio_error_patterns = [
            '_ProactorBaseWritePipeTransport',
            '_loop_writing',
            'proactor_events',
            'Exception in callback',
            'AssertionError'
        ]
        
        # If message contains asyncio error patterns, check if it's from asyncio
        if any(pattern in msg for pattern in asyncio_error_patterns):
            # Check if this is from asyncio's proactor
            if any(keyword in msg.lower() for keyword in ['proactor', 'asyncio', '_overlapped']):
                return False
        
        # Check exception info
        if record.exc_info:
            exc_type, exc_value, exc_traceback = record.exc_info
            if exc_type == AssertionError:
                tb_str = ''.join(traceback.format_tb(exc_traceback))
                # Check traceback for asyncio proactor patterns
                if any(pattern in tb_str for pattern in ['_ProactorBaseWritePipeTransport', '_loop_writing', 'proactor_events']):
                    return False
                # Also check if it's a general AssertionError in asyncio context
                if 'asyncio' in tb_str.lower() and 'proactor' in tb_str.lower():
                    return False
        
        return True

# Apply filter to root logger to catch all asyncio errors
logging.getLogger().addFilter(AsyncioErrorFilter())
# Also suppress asyncio logger specifically (reduces noise from asyncio itself)
logging.getLogger('asyncio').setLevel(logging.WARNING)

# Suppress asyncio's default exception handler for these specific errors
# Also intercept stderr output for asyncio errors that bypass logging
if sys.platform == 'win32':
    _original_stderr_write = sys.stderr.write
    
    def stderr_write_filter(text):
        """Filter stderr to suppress asyncio ProactorEventLoop errors"""
        if isinstance(text, str):
            # Check for asyncio ProactorEventLoop AssertionError patterns
            if 'AssertionError' in text:
                if any(keyword in text for keyword in [
                    '_ProactorBaseWritePipeTransport',
                    '_loop_writing',
                    'proactor_events',
                    'Exception in callback'
                ]):
                    # Suppress this error output
                    return
        return _original_stderr_write(text)
    
    sys.stderr.write = stderr_write_filter

# Dashboard (optional) - single import attempt
DASHBOARD_OK = False
try:
    from dashboard.server import send_to_dashboard, update_dashboard_stats, start_dashboard_background, register_stage_engines  # type: ignore
    DASHBOARD_OK = True
    log.info("Dashboard module imported successfully")
except Exception as e:
    DASHBOARD_OK = False
    def send_to_dashboard(*a, **k): pass
    def update_dashboard_stats(*a, **k): pass
    def start_dashboard_background(): pass
    def register_stage_engines(*a, **k): pass
    # Log the error so we know why dashboard isn't available
    log.warning(f"Dashboard not available: {e}")

# Stage 1 Fallback - Direct Sysmon Event Log reader (if NxLog unavailable)
SYSMON_FALLBACK_AVAILABLE = False
try:
    from stage1_collection.sysmon_listener_pro import SysmonListenerPro  # type: ignore
    SYSMON_FALLBACK_AVAILABLE = True
    log.info("Sysmon direct Event Log reader available as fallback")
except Exception as e:
    SysmonListenerPro = None
    log.debug("Sysmon direct Event Log reader not available: %s", e)

class UnifiedEDRLauncher:
    def __init__(self, host="127.0.0.1", port=5050, stage3_callback: Optional[Callable[[Dict[str, Any]], None]] = None, 
                 enable_sysmon_fallback: bool = True, sysmon_bookmark_path: Optional[str] = None,
                 stage3_model_path: Optional[str] = None, stage3_threshold: float = 50.0,
                 stage3_yara_rules_path: Optional[str] = None,  # YARA rules for Stage 3
                 stage4_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 stage4_tabnet_model_path: Optional[str] = None,
                 stage4_ensemble_model_path: Optional[str] = None,
                 stage5_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 training_mode: bool = False,
                 dataset_dir: Optional[str] = None,
                 label_file: Optional[str] = None,
                 background_sample_rate: float = 0.01):
        self.host = host
        self.port = port
        self.stage3_callback = stage3_callback  # Legacy
        self.stage4_callback = stage4_callback  # Legacy
        self.stage5_callback = stage5_callback  # New: actual Stage 5 callback
        self.server = None
        self.running = True
        self.total_processed = 0
        self.total_promoted = 0  # Stage 2 promotions
        self.total_stage3_promoted = 0  # Stage 3 → Stage 4 promotions
        self.total_stage4_promoted = 0  # Stage 4 → Stage 5 promotions
        # track client handler tasks for clean cancellation
        self._client_tasks = set()
        # Sysmon fallback (direct Event Log reader)
        self.enable_sysmon_fallback = enable_sysmon_fallback and SYSMON_FALLBACK_AVAILABLE
        self.sysmon_listener = None
        self.sysmon_bookmark_path = sysmon_bookmark_path or "sysmon_bookmark.xml"
        
        # NxLog process management
        self.nxlog_process = None
        self.nxlog_config_path = None

        # Training / dataset recording
        self.training_mode = bool(training_mode)
        self.background_sample_rate = float(background_sample_rate)
        self.dataset_recorder = None

        # Load central config once (safe fallback to defaults if unavailable)
        self.edr_config = None
        if EDR_CONFIG_AVAILABLE and get_edr_config:
            try:
                self.edr_config = get_edr_config()
            except Exception:
                log.exception("Failed to load central EDR config; using built-in defaults")

        stage3_tier_low_max = 59.0
        stage3_tier_medium_max = 79.0
        stage3_tier_high_max = 94.0
        stage3_high_band_split_score = 87.0
        stage4_enable_cache = True
        stage4_cache_ttl_sec = 300
        stage4_cache_max_size = 5000
        if self.edr_config:
            try:
                stage3_tier_low_max = float(self.edr_config.stage3.tier_low_max)
                stage3_tier_medium_max = float(self.edr_config.stage3.tier_medium_max)
                stage3_tier_high_max = float(self.edr_config.stage3.tier_high_max)
                stage3_high_band_split_score = float(self.edr_config.stage3.high_band_split_score)
                stage4_enable_cache = bool(self.edr_config.stage4.enable_verdict_cache)
                stage4_cache_ttl_sec = int(self.edr_config.stage4.verdict_cache_ttl_sec)
                stage4_cache_max_size = int(self.edr_config.stage4.verdict_cache_max_size)
            except Exception:
                log.exception("Invalid Stage3/Stage4 config values; using built-in defaults")

        if self.training_mode:
            try:
                from stage3_feature_extraction.dataset_recorder import Stage3DatasetRecorder  # type: ignore
                if not dataset_dir:
                    dataset_dir = "data/stage3_dataset"
                # Feature names must match MLScorer expectation
                feature_names = []
                try:
                    if STAGE3_READY:
                        # lazy: Stage3Engine uses MLScorer internally
                        from src.stage3_feature_extraction.ml_scorer2 import MLScorer  # type: ignore
                        feature_names = MLScorer.EXPECTED_FEATURES
                except Exception:
                    feature_names = []
                self.dataset_recorder = Stage3DatasetRecorder(
                    dataset_dir=str(dataset_dir),
                    feature_names=feature_names,
                    db_path="src/dashboard/dashboard.db",
                    label_file=label_file,
                )
                log.info(f"TRAIN MODE enabled: recording Stage3 dataset to {dataset_dir}")
            except Exception as e:
                log.warning(f"TRAIN MODE requested but dataset recorder unavailable: {e}")
        
        # Stage 4 engine (initialized first, as Stage 3 will call it)
        self.stage4_engine = None
        if STAGE4_READY and initialize_stage4:
            try:
                # Use stage5_callback if provided, otherwise fall back to stage4_callback
                callback = stage5_callback or stage4_callback or stage3_callback
                self.stage4_engine = initialize_stage4(
                    tabnet_model_path=stage4_tabnet_model_path,
                    ensemble_model_path=stage4_ensemble_model_path,
                    stage5_callback=callback,
                    enable_verdict_cache=stage4_enable_cache,
                    verdict_cache_ttl_sec=stage4_cache_ttl_sec,
                    verdict_cache_max_size=stage4_cache_max_size,
                )
                log.info("Stage 4 engine initialized")
            except Exception:
                log.exception("Failed to initialize Stage 4 engine")
        
        # Stage 3 engine (with YARA and tiered thresholds)
        self.stage3_engine = None
        if STAGE3_READY and initialize_stage3:
            try:
                # Stage 3 should forward to Stage 4 for Medium/Critical tiers
                stage4_callback = self._on_stage3_to_stage4 if self.stage4_engine else (stage4_callback or stage3_callback)
                
                # Immediate response callback for High/Critical tiers
                immediate_response_callback = self._on_stage3_immediate_response
                
                self.stage3_engine = initialize_stage3(
                    model_path=stage3_model_path,
                    threshold=stage3_threshold,
                    tier_low_max=stage3_tier_low_max,
                    tier_medium_max=stage3_tier_medium_max,
                    tier_high_max=stage3_tier_high_max,
                    high_band_split_score=stage3_high_band_split_score,
                    stage4_callback=stage4_callback,
                    yara_rules_path=stage3_yara_rules_path,  # YARA rules for Stage 3
                    immediate_response_callback=immediate_response_callback
                )
                log.info(f"Stage 3 engine initialized with YARA and tiered thresholds (threshold={stage3_threshold})")
                
                # Register stage engines with dashboard for manual promotion
                if DASHBOARD_OK:
                    try:
                        register_stage_engines(stage3_engine=self.stage3_engine, stage4_engine=self.stage4_engine)
                    except Exception:
                        log.warning("Failed to register stage engines with dashboard")
            except Exception:
                log.exception("Failed to initialize Stage 3 engine")
    
    def _on_stage3_to_stage4(self, event: Dict[str, Any]) -> None:
        """Internal handler for Stage 3 → Stage 4 events (Medium/Critical tiers)"""
        if self.stage4_engine:
            try:
                decision = self.stage4_engine.process_event(event)
                if decision.verdict.value in ["malicious", "suspicious"]:
                    self.total_stage4_promoted += 1
                    log.warning(
                        f"Stage4 → Stage5: PID={event.get('ProcessID', '???')} "
                        f"Verdict={decision.verdict.value} Score={decision.score:.2f}"
                    )
            except Exception:
                log.exception("Error in Stage 4 processing")
    
    def _on_stage3_immediate_response(self, event: Dict[str, Any], tier, score: float) -> None:
        """
        Internal handler for Stage 3 immediate responses (High/Critical tiers).
        
        This triggers immediate actions:
        - High (80-94): Kill process, isolate endpoint, block network, create VSS snapshot
        - Critical (95-100): Nuclear response (full kill/suspend/quarantine + memory dump + isolation)
        """
        pid = event.get('ProcessID') or event.get('ProcessId') or '???'
        tier_name = tier.value if hasattr(tier, 'value') else str(tier)
        
        log.critical(
            f"Stage3 IMMEDIATE RESPONSE: PID={pid} Tier={tier_name} Score={score:.2f} - "
            f"Triggering automated response actions"
        )
        
        # TODO: Implement actual response actions (Stage 5)
        # For now, just log and forward to Stage 5 callback if available
        if self.stage5_callback:
            try:
                event['__immediate_response'] = True
                event['__immediate_response_tier'] = tier_name
                event['__immediate_response_score'] = score
                self.stage5_callback(event)
            except Exception:
                log.exception(f"Stage5 callback failed for immediate response (PID {pid})")

    async def _safe_readline(self, reader: asyncio.StreamReader, timeout: float) -> Optional[bytes]:
        """
        Wrapper to read a line with timeout while handling CancelledError / EOF gracefully.
        Returns None on EOF or extraordinary conditions.
        """
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not line:
                return None
            return line
        except asyncio.TimeoutError:
            # no data in this period — return None to allow outer loop to check liveness
            return None
        except (asyncio.CancelledError, RuntimeError):
            return None
        except Exception:
            return None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        log.info(f"NxLog CONNECTED → {peer_str}")
        session = {"processed": 0, "promoted": 0}
        task = asyncio.current_task()
        if task:
            self._client_tasks.add(task)

        try:
            while self.running:
                line = await self._safe_readline(reader, timeout=30.0)
                if line is None:
                    # either timeout or EOF; if EOF break, if timeout continue to allow client to remain connected
                    if reader.at_eof():
                        break
                    # timeout occurred — continue waiting
                    continue

                raw = line.rstrip(b"\r\n")
                if not raw:
                    continue

                try:
                    event = json.loads(raw.decode("utf-8", errors="replace"))
                except Exception:
                    # not JSON; ignore single bad lines
                    continue

                # Ensure every event has a stable UUID (used for labeling + dataset joins)
                if "__event_uuid" not in event:
                    event["__event_uuid"] = str(uuid.uuid4())

                # Normalize ProcessID from NxLog JSON format
                # CRITICAL: NxLog puts actual ProcessId in Message field as text, NOT in EventData!
                # Top-level "ProcessID" (14672) is Sysmon service PID - ALWAYS overwrite it!
                # We must parse Message field or use top-level "ProcessId" (lowercase 'd')
                pid = None
                import re
                
                # Store the top-level ProcessID temporarily (might be Sysmon service PID)
                top_level_pid = event.get("ProcessID")
                   
                # Priority 1: Parse ProcessId from Message field (NxLog format - actual process PID)
                # Message format: "Process Create:\r\n...ProcessId: 1120\r\n..."
                if "Message" in event and isinstance(event["Message"], str):
                    msg = event["Message"]
                    # Look for "ProcessId: 1234" pattern in Message (handle \r\n, spaces, etc.)
                    # Try multiple patterns to be robust
                    patterns = [
                        r'ProcessId:\s*(\d+)',           # Standard: "ProcessId: 1120"
                        r'ProcessId\s*=\s*(\d+)',         # Alternative: "ProcessId=1120"
                        r'ProcessId\s+(\d+)',             # Alternative: "ProcessId 1120"
                    ]
                    for pattern in patterns:
                        match = re.search(pattern, msg, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                        if match:
                            try:
                                pid_val = int(match.group(1))
                                if pid_val > 0:
                                    pid = pid_val
                                    if session["processed"] <= 3:
                                        print(f"[DEBUG] ✓ Extracted PID {pid} from Message field using pattern: {pattern}")
                                    break
                            except (ValueError, TypeError) as e:
                                if session["processed"] <= 3:
                                    print(f"[DEBUG] Regex matched but conversion failed: {e}")
                                continue
                    if pid is None:
                        # Debug: show Message snippet around ProcessId
                        msg_lower = msg.lower()
                        idx = msg_lower.find('processid')
                        if idx >= 0:
                            snippet_start = max(0, idx - 30)
                            snippet_end = min(len(msg), idx + 80)
                            msg_snippet = msg[snippet_start:snippet_end]
                            if session["processed"] <= 3:
                                print(f"[DEBUG] ✗ Could not extract ProcessId from Message. Found 'ProcessId' at position {idx}")
                                print(f"[DEBUG] Message snippet: {repr(msg_snippet)}")
                        elif session["processed"] <= 3:
                            print(f"[DEBUG] ✗ 'ProcessId' not found in Message field at all")
                            print(f"[DEBUG] Message preview (first 200 chars): {msg[:200]}")
                
                # Priority 2: Top-level "ProcessId" field (lowercase 'd' - NxLog sometimes extracts this)
                # NOTE: "ProcessID" (uppercase) is Sysmon service PID - DO NOT USE!
                if pid is None and "ProcessId" in event:
                    try:
                        pid_val = int(event["ProcessId"])
                        if pid_val > 0 and pid_val != 14672:  # Don't use if it's Sysmon service PID
                            pid = pid_val
                    except (ValueError, TypeError):
                        pass

                # Priority 2b: top-level "ProcessID" fallback for synthetic/simple JSON events.
                # In simulator inputs there is no Sysmon Message payload, so ProcessID can be the true PID.
                if pid is None and top_level_pid is not None:
                    try:
                        pid_val = int(top_level_pid)
                        has_message_payload = bool(event.get("Message"))
                        if pid_val > 0 and (pid_val != 14672 or not has_message_payload):
                            pid = pid_val
                    except (ValueError, TypeError):
                        pass
                
                # Priority 3: EventData.ProcessId (if NxLog uses EventData structure)
                if pid is None and "EventData" in event:
                    ed = event["EventData"]
                    if isinstance(ed, dict):
                        for key in ["ProcessId", "process_id"]:  # Don't use "ProcessID" - might be Sysmon
                            if key in ed:
                                try:
                                    pid_val = int(ed[key])
                                    if pid_val > 0 and pid_val != 14672:
                                        pid = pid_val
                                        break
                                except (ValueError, TypeError):
                                    continue
                    elif isinstance(ed, list):
                        for item in ed:
                            if isinstance(item, dict):
                                name = item.get("Name", "")
                                if name in ["ProcessId", "process_id"]:
                                    try:
                                        pid_val = int(item.get("Value") or item.get("Data") or item.get("$value") or 0)
                                        if pid_val > 0 and pid_val != 14672:
                                            pid = pid_val
                                            break
                                    except (ValueError, TypeError):
                                        continue
                
                # NEVER use top-level "ProcessID" (uppercase) - that's Sysmon service PID (14672)!
                # Populate all common field name variants with the CORRECT PID
                if pid is not None:
                    event["ProcessID"] = pid
                    event["ProcessId"] = pid
                    event["process_id"] = pid
                    event["pid"] = pid
                    # Log if we overwrote the Sysmon service PID
                    if top_level_pid and top_level_pid != pid:
                        log.debug(f"Overwrote Sysmon service PID {top_level_pid} with actual process PID {pid}")
                else:
                    # No PID found - log warning with event details
                    log.warning(f"Could not extract ProcessID from event. EventID: {event.get('EventID', '?')}, Top-level ProcessID was: {top_level_pid}, Message preview: {str(event.get('Message', ''))[:100]}")
                
                # Apply unified normalization (after NxLog-specific PID extraction)
                if NORMALIZER_AVAILABLE and EventNormalizer:
                    try:
                        event = EventNormalizer.normalize(event, strict=False)
                    except Exception as e:
                        log.debug(f"Event normalization failed after PID extraction: {e}")

                self.total_processed += 1
                session["processed"] += 1

                # print first few events for debug
                if session["processed"] <= 3:
                    print(f"\n[DEBUG] Event #{session['processed']}")
                    snippet = json.dumps(event, indent=2)
                    print(snippet if len(snippet) < 1200 else snippet[:1200] + " ...")
                    # Debug: Show Message field and ProcessId extraction attempt
                    if "Message" in event:
                        msg = event["Message"]
                        print(f"[DEBUG] Message field type: {type(msg)}, length: {len(msg) if isinstance(msg, str) else 'N/A'}")
                        # Show ProcessId pattern in Message
                        import re
                        pid_match = re.search(r'ProcessId:\s*(\d+)', str(msg), re.IGNORECASE)
                        if pid_match:
                            print(f"[DEBUG] Found ProcessId in Message: {pid_match.group(1)}")
                        else:
                            # Show a snippet of Message around where ProcessId should be
                            msg_str = str(msg)
                            idx = msg_str.lower().find('processid')
                            if idx >= 0:
                                snippet_start = max(0, idx - 50)
                                snippet_end = min(len(msg_str), idx + 100)
                                print(f"[DEBUG] Message snippet around 'ProcessId': {msg_str[snippet_start:snippet_end]}")
                    # Debug: Show what PID was extracted and from where
                    pid_debug = {k: v for k, v in event.items() if 'pid' in k.lower() or (k == 'ProcessID' or k == 'ProcessId')}
                    print(f"[DEBUG] PID-related fields after normalization: {pid_debug}")
                    print(f"[DEBUG] Final extracted PID: {event.get('ProcessID', 'NOT FOUND')}")

                # Stage-2 prefiltering
                promoted = False
                reasons = []
                try:
                    if PREFILTER_READY and _prefmod:
                        # If engine object exists, use it to get structured reasons
                        try:
                            engine = getattr(_prefmod, "_ENGINE", None)
                            if engine and hasattr(engine, "process_event"):
                                promoted, reasons = engine.process_event(event)
                            else:
                                # fallback to function entrypoint
                                promoted = bool(_prefmod.stage2_prefilter(event))
                        except Exception:
                            # last resort fallback
                            promoted = bool(_prefmod.stage2_prefilter(event))
                    else:
                        # no prefilter — default to not promoted
                        promoted = False
                except Exception:
                    log.exception("Prefilter raised an exception")

                # Dataset mode: pass all events through to Stage 3 by design.
                if self.training_mode:
                    promoted = True
                    if "dataset_collection_mode" not in reasons:
                        reasons = list(reasons) if reasons else []
                        reasons.append("dataset_collection_mode")

                # TRAIN MODE: also sample a small fraction of non-promoted events for benign baseline
                sample_background = False
                if self.training_mode and (not promoted):
                    try:
                        sample_background = random.random() < max(0.0, min(1.0, self.background_sample_rate))
                    except Exception:
                        sample_background = False

                # CRITICAL: Feed ALL events to Stage 3's FeatureExtractor continuously
                # This allows it to build per-PID feature profiles over time, not just on promotion
                # Only feature extraction is updated here; ML scoring happens only on promotion
                if STAGE3_READY and self.stage3_engine:
                    try:
                        # Feed event to feature extractor to build up per-PID tracking
                        # This ensures when an event is promoted, features are already populated
                        self.stage3_engine.feature_extractor.process_event(event)
                    except Exception:
                        log.debug("Failed to feed event to Stage 3 feature extractor (non-fatal)", exc_info=True)

                if promoted:
                    session["promoted"] += 1
                    self.total_promoted += 1

                    print("\n" + "═" * 90)
                    print(f" STAGE 2 → STAGE 3 | PID: {event.get('ProcessID', '???')} | Reasons: {reasons}")
                    print("═" * 90 + "\n")

                    # Stage 3: Feature Extraction + Fast ML (with YARA and tiered thresholds)
                    # NOTE: Feature extractor already has this event (from continuous feeding above)
                    stage3_result = None
                    stage3_promoted = False
                    stage3_score = 0.0
                    stage3_tier = "low"
                    if self.stage3_engine:
                        try:
                            stage3_result = self.stage3_engine.process_event(event)
                            stage3_promoted = stage3_result.promoted_to_stage4
                            stage3_score = stage3_result.score
                            stage3_tier = stage3_result.tier.value
                            
                            if stage3_result.immediate_response_triggered:
                                print("\n" + "═" * 90)
                                print(f" STAGE 3 IMMEDIATE RESPONSE | PID: {event.get('ProcessID', '???')} | "
                                      f"Tier: {stage3_tier.upper()} | Score: {stage3_score:.2f} | "
                                      f"YARA: {'MATCHED' if stage3_result.yara_matched else 'no match'}")
                                print("═" * 90 + "\n")
                            
                            if stage3_promoted:
                                self.total_stage3_promoted += 1
                                print("\n" + "═" * 90)
                                print(f" STAGE 3 → STAGE 4 | PID: {event.get('ProcessID', '???')} | "
                                      f"Tier: {stage3_tier.upper()} | ML Score: {stage3_score:.2f} | "
                                      f"YARA: {'MATCHED' if stage3_result.yara_matched else 'no match'}")
                                print("═" * 90 + "\n")
                        except Exception:
                            log.exception("Stage 3 processing failed")

                    # Record dataset row if in training mode (even for LOW tier)
                    if self.training_mode and self.dataset_recorder and stage3_result:
                        try:
                            self.dataset_recorder.record(event)
                        except Exception:
                            log.exception("Dataset recorder failed (promoted path)")

                    # Stage 4: Full Scorer (if Stage 3 promoted)
                    stage4_decision = None
                    if stage3_promoted and self.stage4_engine:
                        try:
                            stage4_decision = self.stage4_engine.process_event(event)
                            if stage4_decision.verdict.value in ["malicious", "suspicious"]:
                                self.total_stage4_promoted += 1
                                print("\n" + "═" * 90)
                                print(f" STAGE 4 → STAGE 5 | PID: {event.get('ProcessID', '???')} | Verdict: {stage4_decision.verdict.value} | Score: {stage4_decision.score:.2f}")
                                print("═" * 90 + "\n")
                        except Exception:
                            log.exception("Stage 4 processing failed")

                    # Dashboard: Send event with stage information
                    try:
                        reasons_list = event.get("__reasons", reasons)
                        evt = dict(event)
                        evt['__stage2'] = True
                        
                        # Add Stage 3 results (already in event from stage3_engine.process_event)
                        if stage3_result:
                            evt['__stage3'] = True
                            evt['__stage3_score'] = stage3_score
                            evt['__stage3_tier'] = stage3_tier
                            evt['__stage3_yara_matched'] = stage3_result.yara_matched
                            evt['__stage3_yara_rules'] = stage3_result.yara_rules
                            
                            # Add YARA info to reasons if matched
                            if stage3_result.yara_matched:
                                reasons_list = list(reasons_list) if reasons_list else []
                                reasons_list.append(f"YARA:{','.join(stage3_result.yara_rules[:3])}")
                        
                        if stage4_decision and stage4_decision.verdict.value in ["malicious", "suspicious"]:
                            # Stage 5: Active Threat (promoted from Stage 4)
                            evt['__stage4'] = True
                            evt['__stage4_verdict'] = stage4_decision.verdict.value
                            evt['__stage4_score'] = stage4_decision.score
                            evt['__stage5'] = True
                        elif stage3_promoted:
                            # Stage 4: Threat Analysis (Medium/Critical tier forwarded to Stage 4)
                            evt['__stage4'] = True
                            if stage4_decision:
                                evt['__stage4_verdict'] = stage4_decision.verdict.value
                                evt['__stage4_score'] = stage4_decision.score
                        elif stage3_result and stage3_result.immediate_response_triggered:
                            # High/Critical tier: Immediate response triggered
                            evt['__stage3_immediate_response'] = True
                            evt['__stage3_tier'] = stage3_tier
                        
                        if DASHBOARD_OK:
                            # Determine stage label for dashboard based on tiered logic
                            if evt.get('__stage5'):
                                # Stage 5: Active Threat (from Stage 4)
                                stage_label = 'stage4'  # Show as Active Threat
                                send_to_dashboard(evt, promoted=True, reasons=reasons_list, stage_override=stage_label)
                                update_dashboard_stats(promoted=True, reasons=reasons_list)
                            elif evt.get('__stage3_immediate_response'):
                                # High/Critical tier: Show as Active Threat (immediate response)
                                stage_label = 'stage4'  # Show as Active Threat
                                send_to_dashboard(evt, promoted=True, reasons=reasons_list, stage_override=stage_label)
                                update_dashboard_stats(promoted=True, reasons=reasons_list)
                            elif evt.get('__stage4'):
                                # Medium/Critical tier forwarded to Stage 4: Show as Threat Analysis
                                stage_label = 'stage3'  # Show as Threat Analysis
                                send_to_dashboard(evt, promoted=False, reasons=reasons_list, stage_override=stage_label)
                                update_dashboard_stats(promoted=False, reasons=reasons_list)
                            elif evt.get('__stage3'):
                                # Stage 3 scored but Low tier: Show as Threat Analysis (for visibility)
                                stage_label = 'stage3'  # Show as Threat Analysis
                                send_to_dashboard(evt, promoted=False, reasons=reasons_list, stage_override=stage_label)
                                update_dashboard_stats(promoted=False, reasons=reasons_list)
                            # Stage 2 events stay under the hood
                    except Exception:
                        log.exception("Failed during promotion delivery")
                else:
                    # non-promoted events: Stage 2 stays under the hood, only send Stage 1 events to dashboard
                    # Stage 2 events are NOT sent to dashboard (they remain under the hood)
                    try:
                        if DASHBOARD_OK:
                            # Only update stats for Stage 1 events (non-promoted)
                            update_dashboard_stats(promoted=False, reasons=[])
                            # Send as Stage 1 (Event Collection)
                            evt = dict(event)
                            send_to_dashboard(evt, promoted=False, reasons=[], stage_override='stage1')
                    except Exception:
                        log.exception("Failed to deliver event to dashboard")

                    # TRAIN MODE: sampled background Stage3 scoring + recording (does not alert)
                    # NOTE: Feature extractor already has this event (from continuous feeding above)
                    if self.training_mode and sample_background and self.stage3_engine:
                        try:
                            # Mark as training sample so feature extractor allows new processes
                            event['__training_sample'] = True
                            event['__manually_promoted'] = True  # Allow feature extraction for new processes
                            stage3_result_bg = self.stage3_engine.process_event(event)
                            if self.dataset_recorder:
                                self.dataset_recorder.record(event)
                        except Exception:
                            log.exception("Dataset recorder failed (background sample)")

        finally:
            log.info(f"NxLog disconnected | Processed: {session['processed']} | Promoted: {session['promoted']}")
            try:
                # On Windows Proactor event loop, we need to handle writer closure carefully
                # to avoid AssertionError in _loop_writing
                if writer.can_write_eof():
                    writer.write_eof()
                writer.close()
                # Give a small delay for Windows Proactor to handle the close
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except (asyncio.TimeoutError, AssertionError):
                    # Windows Proactor sometimes has race conditions - this is harmless
                    pass
            except (AssertionError, OSError, ConnectionError):
                # Windows Proactor AssertionError is harmless - connection is closed anyway
                pass
            except Exception:
                # Any other exception during cleanup - log but don't crash
                log.debug("Error during writer cleanup (non-critical)", exc_info=True)
            if task:
                self._client_tasks.discard(task)

    def _process_event_from_sysmon(self, event: Dict[str, Any]):
        """
        Process event from sysmon_listener_pro (direct Event Log reader).
        This callback bridges the threading-based sysmon_listener_pro to our async event processing.
        """
        if not self.running:
            return
        
        # Use unified event normalizer if available
        if NORMALIZER_AVAILABLE and EventNormalizer:
            try:
                event = EventNormalizer.normalize(event, strict=False)
            except Exception as e:
                log.debug(f"Event normalization failed: {e}, using fallback")
                # Fallback to manual normalization
                if "ProcessID" not in event:
                    for key in ["ProcessId", "process_id", "pid"]:
                        if key in event:
                            try:
                                event["ProcessID"] = int(event[key])
                                event["ProcessId"] = event["ProcessID"]
                                event["process_id"] = event["ProcessID"]
                                event["pid"] = event["ProcessID"]
                                break
                            except (ValueError, TypeError):
                                continue
        else:
            # Fallback normalization
            if "ProcessID" not in event:
                for key in ["ProcessId", "process_id", "pid"]:
                    if key in event:
                        try:
                            event["ProcessID"] = int(event[key])
                            event["ProcessId"] = event["ProcessID"]
                            event["process_id"] = event["ProcessID"]
                            event["pid"] = event["ProcessID"]
                            break
                        except (ValueError, TypeError):
                            continue
        
        self.total_processed += 1

        # Ensure UUID for sysmon fallback events too
        if "__event_uuid" not in event:
            event["__event_uuid"] = str(uuid.uuid4())
        
        # Stage-2 prefiltering (same as NxLog events)
        promoted = False
        reasons = []
        try:
            if PREFILTER_READY and _prefmod:
                try:
                    engine = getattr(_prefmod, "_ENGINE", None)
                    if engine and hasattr(engine, "process_event"):
                        promoted, reasons = engine.process_event(event)
                    else:
                        promoted = bool(_prefmod.stage2_prefilter(event))
                except Exception:
                    promoted = bool(_prefmod.stage2_prefilter(event))
        except Exception:
            log.exception("Prefilter raised an exception")

        # Dataset mode: pass all events through to Stage 3 by design.
        if self.training_mode:
            promoted = True
            if "dataset_collection_mode" not in reasons:
                reasons = list(reasons) if reasons else []
                reasons.append("dataset_collection_mode")

        # TRAIN MODE: sample background too
        sample_background = False
        if self.training_mode and (not promoted):
            try:
                sample_background = random.random() < max(0.0, min(1.0, self.background_sample_rate))
            except Exception:
                sample_background = False

        # CRITICAL: Feed ALL events to Stage 3's FeatureExtractor continuously (same as NxLog path)
        if STAGE3_READY and self.stage3_engine:
            try:
                self.stage3_engine.feature_extractor.process_event(event)
            except Exception:
                log.debug("Failed to feed event to Stage 3 feature extractor (non-fatal)", exc_info=True)

        if promoted:
            self.total_promoted += 1
            print("\n" + "═" * 90)
            print(f" STAGE 2 → STAGE 3 | PID: {event.get('ProcessID', '???')} | Reasons: {reasons}")
            print("═" * 90 + "\n")

        # Stage 3: Feature Extraction + Fast ML (with YARA and tiered thresholds)
        # NOTE: Feature extractor already has this event (from continuous feeding above)
        stage3_result = None
        stage3_promoted = False
        stage3_score = 0.0
        stage3_tier = "low"
        if promoted and self.stage3_engine:
            try:
                stage3_result = self.stage3_engine.process_event(event)
                stage3_promoted = stage3_result.promoted_to_stage4
                stage3_score = stage3_result.score
                stage3_tier = stage3_result.tier.value
                
                if stage3_result.immediate_response_triggered:
                    print("\n" + "═" * 90)
                    print(f" STAGE 3 IMMEDIATE RESPONSE | PID: {event.get('ProcessID', '???')} | "
                          f"Tier: {stage3_tier.upper()} | Score: {stage3_score:.2f} | "
                          f"YARA: {'MATCHED' if stage3_result.yara_matched else 'no match'}")
                    print("═" * 90 + "\n")
                
                if stage3_promoted:
                    self.total_stage3_promoted += 1
                    print("\n" + "═" * 90)
                    print(f" STAGE 3 → STAGE 4 | PID: {event.get('ProcessID', '???')} | "
                          f"Tier: {stage3_tier.upper()} | ML Score: {stage3_score:.2f} | "
                          f"YARA: {'MATCHED' if stage3_result.yara_matched else 'no match'}")
                    print("═" * 90 + "\n")
            except Exception:
                log.exception("Stage 3 processing failed")

            if self.training_mode and self.dataset_recorder and stage3_result:
                try:
                    self.dataset_recorder.record(event)
                except Exception:
                    log.exception("Dataset recorder failed (sysmon promoted path)")

        # Background sample path (sysmon)
        if self.training_mode and sample_background and self.stage3_engine:
            try:
                # Mark as training sample so feature extractor allows new processes
                event['__training_sample'] = True
                event['__manually_promoted'] = True  # Allow feature extraction for new processes
                stage3_result_bg = self.stage3_engine.process_event(event)
                if self.dataset_recorder:
                    self.dataset_recorder.record(event)
            except Exception:
                log.exception("Dataset recorder failed (sysmon background sample)")

        # Stage 4: Full Scorer (if Stage 3 promoted)
        stage4_decision = None
        if stage3_promoted and self.stage4_engine:
            try:
                stage4_decision = self.stage4_engine.process_event(event)
                if stage4_decision.verdict.value in ["malicious", "suspicious"]:
                    self.total_stage4_promoted += 1
                    print("\n" + "═" * 90)
                    print(f" STAGE 4 → STAGE 5 | PID: {event.get('ProcessID', '???')} | Verdict: {stage4_decision.verdict.value} | Score: {stage4_decision.score:.2f}")
                    print("═" * 90 + "\n")
            except Exception:
                log.exception("Stage 4 processing failed")

        # Dashboard + stage5 callback
        try:
            reasons_list = event.get("__reasons", reasons)
            evt = dict(event)
            evt['__stage2'] = True if promoted else False
            
            if stage4_decision and stage4_decision.verdict.value in ["malicious", "suspicious"]:
                # Stage 5: Active Threat
                evt['__stage3'] = True
                evt['__stage3_score'] = stage3_score
                evt['__stage4'] = True
                evt['__stage4_verdict'] = stage4_decision.verdict.value
                evt['__stage4_score'] = stage4_decision.score
                evt['__stage5'] = True
            elif stage3_promoted:
                # Stage 4: Threat Analysis
                evt['__stage3'] = True
                evt['__stage3_score'] = stage3_score
                evt['__stage4'] = True
                if stage4_decision:
                    evt['__stage4_verdict'] = stage4_decision.verdict.value
                    evt['__stage4_score'] = stage4_decision.score
            elif self.stage3_engine and promoted:
                # Stage 3: Threat Analysis
                evt['__stage3'] = True
                evt['__stage3_score'] = stage3_score
                evt['__stage3_dropped'] = True
            
            if DASHBOARD_OK:
                # Determine stage label
                if evt.get('__stage5'):
                    stage_label = 'stage4'  # Active Threat
                    send_to_dashboard(evt, promoted=True, reasons=reasons_list, stage_override=stage_label)
                    update_dashboard_stats(promoted=True, reasons=reasons_list)
                elif evt.get('__stage4'):
                    stage_label = 'stage3'  # Threat Analysis
                    send_to_dashboard(evt, promoted=False, reasons=reasons_list, stage_override=stage_label)
                    update_dashboard_stats(promoted=False, reasons=reasons_list)
                elif evt.get('__stage3'):
                    stage_label = 'stage3'  # Threat Analysis
                    send_to_dashboard(evt, promoted=False, reasons=reasons_list, stage_override=stage_label)
                    update_dashboard_stats(promoted=False, reasons=reasons_list)
            
            # Stage 5 callback
            if evt.get('__stage5') and (self.stage5_callback or self.stage4_callback or self.stage3_callback):
                callback = self.stage5_callback or self.stage4_callback or self.stage3_callback
                try:
                    callback(event)
                except Exception:
                    log.exception("Stage5 callback failed")
        except Exception:
            log.exception("Failed during event delivery from Sysmon fallback")

    async def start(self):
        log.info("UNIFIED EDR LAUNCHER STARTING...")
        stages = "Stage 1 → TCP Listener | Stage 2 → Prefilter | Stage 3 → Feature Extraction + ML"
        if self.stage3_engine:
            stages += f" (threshold={self.stage3_engine.ml_scorer.get_threshold()})"
        stages += " | Stage 4 → Full Scorer"
        if self.stage4_engine:
            stages += " (Active)"
        else:
            stages += " (Not Available)"
        stages += " | Stage 5 → Ready"
        log.info(stages)
        log.info(f"Listening on {self.host}:{self.port}")

        # start dashboard background if available
        if DASHBOARD_OK:
            try:
                dashboard_thread = threading.Thread(target=start_dashboard_background, daemon=True)
                dashboard_thread.start()
                # Give the dashboard thread a moment to start
                import time
                time.sleep(0.5)
                log.info("Dashboard background started (http://127.0.0.1:8000)")
            except Exception as e:
                log.exception(f"Failed to start dashboard background: {e}")
            # register our internal handler so dashboard actions can reach launcher
            try:
                from dashboard import server as dashboard_server
                dashboard_server.register_stage3_handler(self._on_stage3)
            except Exception:
                log.exception('Failed to register stage3 handler with dashboard')
        else:
            log.warning("Dashboard is not available - check if fastapi and uvicorn are installed")

        # Start NxLog process automatically
        self._start_nxlog()
        
        # Start Sysmon fallback (direct Event Log reader) if enabled
        if self.enable_sysmon_fallback and SysmonListenerPro:
            try:
                self.sysmon_listener = SysmonListenerPro(
                    callback=self._process_event_from_sysmon,
                    bookmark_path=self.sysmon_bookmark_path
                )
                self.sysmon_listener.start()
                log.info("Sysmon direct Event Log reader started (fallback mode)")
            except Exception:
                log.exception("Failed to start Sysmon fallback listener")

        self.server = await asyncio.start_server(self.handle_client, self.host, self.port, reuse_address=True)
        addrs = ", ".join(str(s.getsockname()) for s in self.server.sockets)
        log.info(f"UNIFIED EDR IS NOW LIVE → {addrs}")
        try:
            async with self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            # graceful cancel path
            pass

    def _start_nxlog(self):
        """Start NxLog process automatically"""
        import subprocess
        from pathlib import Path
        
        # Find NxLog executable - check C:\Tools\nxlog first, then Program Files (x86)
        nxlog_paths = [
            Path("C:/Tools/nxlog/nxlog.exe"),
            Path("C:/Program Files (x86)/nxlog/nxlog.exe"),
        ]
        
        nxlog_exe = None
        for path in nxlog_paths:
            if path.exists():
                nxlog_exe = path
                break
        
        if not nxlog_exe:
            log.warning("NxLog executable not found. NxLog will not be started automatically.")
            log.info("Expected locations: C:\\Tools\\nxlog\\nxlog.exe or C:\\Program Files (x86)\\nxlog\\nxlog.exe")
            return
        
        # Find NxLog config file - use repo config if available, otherwise use installed config
        repo_root = Path(__file__).parent.parent
        repo_config = repo_root / "nxlog" / "nxlog.conf"
        
        if repo_config.exists():
            nxlog_config = repo_config
            log.info(f"Using NxLog config from repository: {nxlog_config}")
        else:
            # Use config from NxLog installation directory
            if nxlog_exe.parent.name == "nxlog":
                # If in C:\Tools\nxlog or C:\Program Files (x86)\nxlog, config is in conf subdirectory
                nxlog_config = nxlog_exe.parent / "conf" / "nxlog.conf"
            else:
                # Fallback: assume conf is in parent directory
                nxlog_config = nxlog_exe.parent.parent / "conf" / "nxlog.conf"
            
            if not nxlog_config.exists():
                log.warning(f"NxLog config not found at {nxlog_config}")
                return
            log.info(f"Using NxLog config from installation: {nxlog_config}")
        
        self.nxlog_config_path = nxlog_config
        
        # Start NxLog process: nxlog.exe -f -c "config_path"
        try:
            log.info(f"Starting NxLog: {nxlog_exe} -f -c \"{nxlog_config}\"")
            self.nxlog_process = subprocess.Popen(
                [str(nxlog_exe), "-f", "-c", str(nxlog_config)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            log.info(f"NxLog started with PID {self.nxlog_process.pid}")
        except Exception as e:
            log.error(f"Failed to start NxLog: {e}")
            self.nxlog_process = None
    
    def stop(self):
        self.running = False
        # cancel client tasks
        for t in list(self._client_tasks):
            try:
                t.cancel()
            except Exception:
                pass
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        # Stop NxLog process
        if self.nxlog_process:
            try:
                self.nxlog_process.terminate()
                self.nxlog_process.wait(timeout=5)
                log.info("NxLog process stopped")
            except subprocess.TimeoutExpired:
                self.nxlog_process.kill()
                log.warning("NxLog process force-killed")
            except Exception:
                log.exception("Error stopping NxLog process")
        # Stop Sysmon fallback listener
        if self.sysmon_listener:
            try:
                self.sysmon_listener.stop()
                log.info("Sysmon fallback listener stopped")
            except Exception:
                log.exception("Error stopping Sysmon fallback listener")
        # Flush dataset recorder
        if self.dataset_recorder:
            try:
                self.dataset_recorder.flush()
                log.info("Dataset recorder flushed")
            except Exception:
                log.exception("Failed to flush dataset recorder")
        log.info("Launcher stop requested")

    def _on_stage3(self, msg: Dict[str, Any]):
        """Internal Stage-3 handler called when dashboard requests an action (e.g., jump).
        Calls user-provided stage3_callback if present, otherwise logs the request.
        """
        try:
            log.info("Stage-3 action received: %s", msg)
            if self.stage3_callback:
                try:
                    self.stage3_callback(msg)
                except Exception:
                    log.exception('user stage3_callback failed')
        except Exception:
            log.exception('internal _on_stage3 failed')


# Standalone run (production mode by default)
# Run directly: python src/unified_launcher.py
# For training mode, use: python src/train_launcher.py
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="RDNXSYS EDR - Production Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--stage3-model-path",
        type=str,
        default=None,
        help="Path to trained LightGBM model file for Stage 3 ML scoring"
    )
    parser.add_argument(
        "--stage3-threshold",
        type=float,
        default=50.0,
        help="Stage 3 ML score threshold for promotion to Stage 4 (0-100, default: 50.0)"
    )
    parser.add_argument(
        "--stage3-yara-rules-path",
        type=str,
        default=None,
        help="Path to YARA rules file or directory for Stage 3 (default: uses bundled rules)"
    )
    parser.add_argument(
        "--stage4-model-path",
        type=str,
        default=str(Path("models") / "stage4_v2_phasea" / "stage4_v2_phasea.txt"),
        help="Path to trained Stage 4 LightGBM model (.txt). Default: models/stage4_v2_phasea/stage4_v2_phasea.txt"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="TCP listener host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5050,
        help="TCP listener port (default: 5050)"
    )
    parser.add_argument(
        "--enable-sysmon-fallback",
        action="store_true",
        default=True,
        help="Enable Sysmon Event Log fallback if NxLog unavailable (default: True)"
    )
    parser.add_argument(
        "--dataset-mode",
        action="store_true",
        default=False,
        help="Enable dataset collection mode (passes all events to Stage 3)"
    )
    parser.add_argument(
        "--session-name",
        type=str,
        default=None,
        help="Dataset collection session name (required for --dataset-mode)"
    )
    parser.add_argument(
        "--dataset-dir",
        type=str,
        default=None,
        help="Dataset output directory (default: data/dataset_sessions/<session>)"
    )
    parser.add_argument(
        "--label-file",
        type=str,
        default=None,
        help="Optional label rules JSON file for dataset labeling"
    )
    parser.add_argument(
        "--background-sample-rate",
        type=float,
        default=0.01,
        help="Background sample rate for dataset mode (default: 0.01)"
    )
    
    args = parser.parse_args()
    
    log.info("=" * 80)
    log.info("RDNXSYS EDR - %s", "DATASET MODE" if args.dataset_mode else "PRODUCTION MODE (default)")
    log.info("=" * 80)
    log.info("")
    log.info("For training mode, use: python src/train_launcher.py")
    log.info("For production mode, use: python src/unified_launcher.py")
    log.info("")
    
    if args.stage3_model_path:
        log.info(f"Stage 3 Model: {args.stage3_model_path}")
        log.info(f"Stage 3 Threshold: {args.stage3_threshold}")
    else:
        log.info("Stage 3 Model: Not specified (using static/rule-based scorer)")
    if args.stage4_model_path:
        log.info(f"Stage 4 Model: {args.stage4_model_path}")
    
    dataset_dir = None
    training_mode = False
    if args.dataset_mode:
        training_mode = True
        if not args.session_name:
            log.error("--session-name is required when using --dataset-mode")
            sys.exit(2)
        if MODE_MANAGER_AVAILABLE:
            try:
                manager = get_mode_manager()
                manager.set_mode(RunMode.DATASET_COLLECTION, session_name=args.session_name)
                log.info("Dataset mode enabled: session=%s", args.session_name)
            except Exception as e:
                log.warning("Failed to set dataset mode in configuration: %s", e)
        dataset_dir = args.dataset_dir or str(Path("data") / "dataset_sessions" / args.session_name)
    
    # Create launcher
    launcher = UnifiedEDRLauncher(
        host=args.host,
        port=args.port,
        training_mode=training_mode,
        stage3_model_path=args.stage3_model_path,
        stage3_threshold=args.stage3_threshold,
        stage3_yara_rules_path=args.stage3_yara_rules_path,
        stage4_tabnet_model_path=args.stage4_model_path,
        enable_sysmon_fallback=args.enable_sysmon_fallback,
        dataset_dir=dataset_dir,
        label_file=args.label_file,
        background_sample_rate=args.background_sample_rate,
    )

    loop = asyncio.new_event_loop()
    
    # Set custom exception handler to suppress ProactorEventLoop AssertionErrors on Windows
    if sys.platform == 'win32':
        def exception_handler(loop, context):
            """Filter out ProactorEventLoop AssertionError exceptions"""
            exception = context.get('exception')
            message = context.get('message', '')
            
            # Suppress ProactorBaseWritePipeTransport AssertionErrors
            if isinstance(exception, AssertionError):
                exception_str = str(exception)
                if any(keyword in exception_str or keyword in message for keyword in [
                    '_ProactorBaseWritePipeTransport',
                    '_loop_writing',
                    'proactor_events'
                ]):
                    # Suppress this exception - it's a harmless Windows asyncio bug
                    return
            
            # Call default handler for other exceptions
            loop.default_exception_handler(context)
        
        loop.set_exception_handler(exception_handler)
    asyncio.set_event_loop(loop)

    def _on_signal(sig, frame):
        log.info("Signal received, shutting down...")
        launcher.stop()
        # cancel loop tasks
        for task in asyncio.all_tasks(loop):
            task.cancel()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    try:
        loop.run_until_complete(launcher.start())
    except KeyboardInterrupt:
        log.info("Stopped by KeyboardInterrupt")
    except Exception:
        log.exception("Launcher crashed")
    finally:
        try:
            loop.stop()
        except Exception:
            pass
        log.info("UNIFIED EDR SHUTDOWN COMPLETE")
