"""
Stage 3 Engine: Feature Extraction + Fast ML Scoring

Orchestrates feature extraction and ML scoring for events promoted from Stage 2.
Only processes events that passed Stage 2 prefiltering.
"""

import logging
import threading
import time
from typing import Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum

from .feature_extractor import FeatureExtractor
from .ml_scorer2 import MLScorer
from .yara_scanner import YaraScanner
from .genealogy_builder import ProcessGenealogy

logger = logging.getLogger("stage3_engine")


class RiskTier(Enum):
    """Risk tier levels"""
    LOW = "low"           # 0-59: Clearly benign
    MEDIUM = "medium"     # 60-79: Possible threat, needs Stage 4 confirmation
    HIGH = "high"         # 80-94: Strong ransomware signal, immediate response
    CRITICAL = "critical" # 95-100: Near-certain ransomware, nuclear response


@dataclass
class Stage3Result:
    """Result from Stage 3 processing"""
    tier: RiskTier
    score: float
    yara_matched: bool
    yara_rules: list
    promoted_to_stage4: bool
    immediate_response_triggered: bool
    reason: str


class Stage3Engine:
    """
    Stage 3 Engine: Feature Extraction + Fast ML Scoring
    
    Receives events promoted from Stage 2, extracts comprehensive features,
    scores using LightGBM, and forwards to Stage 4 if score >= threshold.
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = 50.0,
        tier_low_max: float = 59.0,
        tier_medium_max: float = 79.0,
        tier_high_max: float = 94.0,
        high_band_split_score: float = 87.0,
        stage4_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        feature_window_sec: int = 300,
        cleanup_sec: int = 600,
        yara_rules_path: Optional[str] = None,
        immediate_response_callback: Optional[Callable[[Dict[str, Any], RiskTier, float], None]] = None
    ):
        """
        Initialize Stage 3 Engine with YARA scanner and tiered thresholds.
        
        Args:
            model_path: Path to LightGBM model file (optional)
            threshold: Legacy ML score threshold (0-100, default 50.0) - kept for compatibility
            tier_low_max: Upper bound for LOW tier (default 59.0)
            tier_medium_max: Upper bound for MEDIUM tier (default 79.0)
            tier_high_max: Upper bound for HIGH tier (default 94.0)
            high_band_split_score: Split score for HIGH band policy (default 87.0)
            stage4_callback: Callback function for events promoted to Stage 4 (Medium/Critical tiers)
            feature_window_sec: Time window for feature tracking (default 5 minutes)
            cleanup_sec: Cleanup processes older than this (default 10 minutes)
            yara_rules_path: Path to YARA rules file or directory (300-400 curated rules)
            immediate_response_callback: Callback for High/Critical tiers requiring immediate response
        """
        self.feature_extractor = FeatureExtractor(
            window_sec=feature_window_sec,
            cleanup_sec=cleanup_sec
        )
        # Start background cleanup thread for feature extractor
        self.feature_extractor.start_cleanup_thread()
        
        self.ml_scorer = MLScorer(
            model_path=model_path,
            threshold=threshold,
            tier_low_max=tier_low_max,
            tier_medium_max=tier_medium_max,
            tier_high_max=tier_high_max,
        )
        self.high_band_split_score = float(high_band_split_score)
        if not (80.0 <= self.high_band_split_score <= 94.0):
            logger.warning(
                "Invalid high_band_split_score=%s; falling back to 87.0",
                self.high_band_split_score,
            )
            self.high_band_split_score = 87.0
        self.stage4_callback = stage4_callback
        self.immediate_response_callback = immediate_response_callback
        
        # Initialize YARA scanner
        self.yara_scanner = YaraScanner(yara_rules_path=yara_rules_path)
        
        # Initialize Process Genealogy builder (for visualization only, NOT used for ML scoring)
        self.genealogy_builder = ProcessGenealogy(
            window_sec=3600,  # 1 hour window for genealogy
            cleanup_sec=7200  # 2 hour cleanup
        )
        
        self.total_processed = 0
        self.total_promoted_to_stage4 = 0
        self.total_dropped = 0
        self.total_immediate_responses = 0
        self._lock = threading.RLock()
        
        # Statistics by tier
        self.tier_distribution = {
            'low': 0,      # 0-59
            'medium': 0,   # 60-79
            'high': 0,     # 80-94
            'critical': 0  # 95-100
        }
        
        logger.info(f"Stage3Engine initialized (YARA={'enabled' if self.yara_scanner.is_available() else 'disabled'})")
    
    def process_event(self, event: Dict[str, Any]) -> Stage3Result:
        """
        Process an event promoted from Stage 2 with YARA scanning and tiered thresholds.
        
        Args:
            event: Event dictionary from Stage 2 (must have ProcessID)
            
        Returns:
            Stage3Result with tier, score, YARA results, and action taken
        """
        try:
            # Extract PID and image path with validation
            pid = None
            for k in ("ProcessID", "ProcessId", "process_id", "pid"):
                if k in event:
                    try:
                        pid_candidate = int(event[k])
                        # Validate PID range (Windows PIDs are 4-65535, but allow 1-65535 for safety)
                        if 1 <= pid_candidate <= 65535:
                            pid = pid_candidate
                            break
                        else:
                            logger.warning(f"Stage3: Invalid PID value {pid_candidate} (out of range 1-65535)")
                    except (ValueError, TypeError):
                        continue
            
            if not pid:
                logger.warning("Stage3: Event missing PID, dropping")
                return Stage3Result(
                    tier=RiskTier.LOW,
                    score=0.0,
                    yara_matched=False,
                    yara_rules=[],
                    promoted_to_stage4=False,
                    immediate_response_triggered=False,
                    reason="missing_pid"
                )
            
            with self._lock:
                self.total_processed += 1
            
            # Get image path for YARA scanning
            image_path = event.get("Image") or event.get("image") or event.get("ImagePath") or event.get("image_path")
            
            # Check if this is a manual promotion or training sample (allows feature extraction even for very new processes)
            is_manual_promotion = event.get("__manually_promoted", False)
            is_training_sample = event.get("__training_sample", False)
            allow_new_process = is_manual_promotion or is_training_sample
            
            # NOTE: Feature extractor should already have this event processed (from continuous feeding in launcher)
            # But we call it again here to ensure it's updated (idempotent - safe to call multiple times)
            # This handles edge cases like manual promotions from dashboard where event wasn't pre-fed
            self.feature_extractor.process_event(event)
            
            # Update genealogy builder with this event (for visualization only, NOT for ML scoring)
            self.genealogy_builder.add_event(event)
            
            # Extract feature vector (allow new processes for manual promotions or training samples)
            feature_vector = self.feature_extractor.extract_feature_vector(pid, allow_new_process=allow_new_process)
            
            # Early validation: Check feature vector before expensive YARA scan
            if feature_vector is None:
                # Get diagnostics for better error reporting
                diagnostics = self.feature_extractor.get_feature_diagnostics(pid)
                reason_msg = "insufficient_data"
                actionable_guidance = []
                
                if diagnostics:
                    missing = diagnostics.get("missing_critical_events", [])
                    event_types = diagnostics.get("event_types_seen", [])
                    events_seen = diagnostics.get("events_seen", 0)
                    data_quality = diagnostics.get("data_quality", "none")
                    
                    if missing:
                        reason_msg = f"insufficient_data_missing_{'_'.join([m.split()[0].lower() for m in missing[:2]])}"
                    
                    # Provide actionable guidance
                    if "PROCESS_CREATE" in str(missing):
                        actionable_guidance.append("Promote a Process Create event (EventID 1) first to initialize the process")
                    
                    if "FILE_CREATE" in str(missing) and "NETWORK_CONNECT" in event_types:
                        actionable_guidance.append("File I/O events (EventID 11) are needed for file-based features")
                    
                    if events_seen == 1:
                        actionable_guidance.append("Only 1 event seen - promote multiple events for the same PID to build features")
                    
                    if data_quality == "none":
                        actionable_guidance.append("No process data available - ensure ProcessID is present in the event")
                    
                    logger.warning(
                        f"Stage3: PID {pid} - insufficient data for scoring.\n"
                        f"  Events seen: {events_seen}\n"
                        f"  Event types: {event_types}\n"
                        f"  Data quality: {data_quality}\n"
                        f"  Missing: {missing}\n"
                        f"  Guidance: {'; '.join(actionable_guidance) if actionable_guidance else 'None'}"
                    )
                
                return Stage3Result(
                    tier=RiskTier.LOW,
                    score=0.0,
                    yara_matched=False,
                    yara_rules=[],
                    promoted_to_stage4=False,
                    immediate_response_triggered=False,
                    reason=reason_msg
                )
            
            # Get diagnostics for better error reporting (after we know features exist)
            diagnostics = self.feature_extractor.get_feature_diagnostics(pid)
            
            # Feature validation: Check if PID exists and process was initialized
            if not pid:
                logger.warning("Stage3: Feature validation failed - PID is None or invalid")
                return Stage3Result(
                    tier=RiskTier.LOW,
                    score=0.0,
                    yara_matched=False,
                    yara_rules=[],
                    promoted_to_stage4=False,
                    immediate_response_triggered=False,
                    reason="validation_failed_no_pid"
                )
            
            if feature_vector is None:
                # Insufficient data, wait for more events
                reason_msg = "insufficient_data"
                actionable_guidance = []
                
                if diagnostics:
                    missing = diagnostics.get("missing_critical_events", [])
                    event_types = diagnostics.get("event_types_seen", [])
                    events_seen = diagnostics.get("events_seen", 0)
                    data_quality = diagnostics.get("data_quality", "none")
                    
                    if missing:
                        reason_msg = f"insufficient_data_missing_{'_'.join([m.split()[0].lower() for m in missing[:2]])}"
                    
                    # Provide actionable guidance
                    if "PROCESS_CREATE" in str(missing):
                        actionable_guidance.append("Promote a Process Create event (EventID 1) first to initialize the process")
                    
                    if "FILE_CREATE" in str(missing) and "NETWORK_CONNECT" in event_types:
                        actionable_guidance.append("File I/O events (EventID 11) are needed for file-based features")
                    
                    if events_seen == 1:
                        actionable_guidance.append("Only 1 event seen - promote multiple events for the same PID to build features")
                    
                    if data_quality == "none":
                        actionable_guidance.append("No process data available - ensure ProcessID is present in the event")
                    
                    logger.warning(
                        f"Stage3: PID {pid} - insufficient data for scoring.\n"
                        f"  Events seen: {events_seen}\n"
                        f"  Event types: {event_types}\n"
                        f"  Data quality: {data_quality}\n"
                        f"  Missing critical events: {missing}\n"
                        f"  Guidance: {'; '.join(actionable_guidance) if actionable_guidance else 'Wait for more events or promote Process Create event'}"
                    )
                else:
                    logger.debug(f"Stage3: PID {pid} - insufficient data for scoring (no diagnostics available)")
                    actionable_guidance = ["Diagnostics unavailable - check if PID is valid and process exists"]
                
                # Annotate event with diagnostics for dashboard
                event['__stage3'] = True
                event['__stage3_score'] = 0.0
                event['__stage3_tier'] = "low"
                event['__stage3_features'] = {}
                event['__stage3_timestamp'] = time.time()
                event['__stage3_yara_matched'] = False
                event['__stage3_yara_rules'] = []
                event['__stage3_yara_confidence'] = 0.0
                if diagnostics:
                    event['__stage3_data_quality'] = diagnostics.get("data_quality", "none")
                    event['__stage3_feature_diagnostics'] = diagnostics
                    event['__stage3_actionable_guidance'] = actionable_guidance
                
                return Stage3Result(
                    tier=RiskTier.LOW,
                    score=0.0,
                    yara_matched=False,
                    yara_rules=[],
                    promoted_to_stage4=False,
                    immediate_response_triggered=False,
                    reason=reason_msg
                )
            
            # Feature validation: Check feature vector completeness
            if not feature_vector:
                logger.warning(f"Stage3: Feature validation failed - empty feature vector for PID {pid}")
                return Stage3Result(
                    tier=RiskTier.LOW,
                    score=0.0,
                    yara_matched=False,
                    yara_rules=[],
                    promoted_to_stage4=False,
                    immediate_response_triggered=False,
                    reason="validation_failed_empty_features"
                )
            
            # Validate feature vector has expected keys (at least some features)
            expected_feature_count = len(getattr(self.ml_scorer, "feature_names", [])) or 51
            actual_feature_count = len(feature_vector)
            if actual_feature_count < expected_feature_count * 0.5:  # At least 50% of features
                logger.warning(
                    f"Stage3: Feature validation warning - only {actual_feature_count}/{expected_feature_count} "
                    f"features extracted for PID {pid}"
                )
            
            # Run YARA scan (fast, <2ms)
            yara_matched = False
            yara_rules = []
            yara_raw_confidence = 0.0
            yara_weighted_confidence = 0.0
            yara_context = "UNKNOWN"
            yara_context_weight = 0.1
            yara_boost = 0.0
            yara_downweight_reason = ""
            yara_escalation_allowed = True
            behavioral_signal_count = 0
            
            if self.yara_scanner.is_available():
                try:
                    yara_details = self.yara_scanner.scan_process_detailed(
                        pid=pid,
                        image_path=image_path,
                        scan_memory=True  # Scan memory regions on Windows
                    )
                    yara_matched = bool(yara_details.get("matched"))
                    yara_rules = list(yara_details.get("matched_rules") or [])
                    yara_raw_confidence = float(yara_details.get("raw_confidence") or 0.0)
                    yara_weighted_confidence = float(yara_details.get("weighted_confidence") or 0.0)
                    yara_context = str(yara_details.get("primary_context") or "UNKNOWN")
                    yara_context_weight = float(yara_details.get("context_weight") or 0.1)

                    # Populate ML features (context-aware)
                    contexts = yara_details.get("contexts") or {}
                    feature_vector['yara_match_memory'] = 1.0 if contexts.get("MEMORY") else 0.0
                    feature_vector['yara_match_executable'] = 1.0 if contexts.get("EXECUTABLE_FILE") else 0.0
                    feature_vector['yara_match_script'] = 1.0 if contexts.get("SCRIPT_FILE") else 0.0
                    feature_vector['yara_match_document'] = 1.0 if contexts.get("DOCUMENT_FILE") else 0.0
                    feature_vector['yara_match_ads'] = 1.0 if contexts.get("ADS_METADATA") else 0.0
                    feature_vector['yara_weighted_confidence'] = yara_weighted_confidence

                    if yara_matched:
                        logger.info(
                            f"Stage3: YARA match for PID {pid}: ctx={yara_context} "
                            f"raw_conf={yara_raw_confidence:.2f} weighted={yara_weighted_confidence:.2f} "
                            f"rules={yara_rules[:3]}"
                        )
                except Exception:
                    logger.debug(f"YARA scan error for PID {pid}")
            
            # Score using ML/static model (YARA boost handled below, context-aware)
            base_score = self.ml_scorer.score(feature_vector)

            # Count non-YARA behavioral signals (for corroboration on low-trust YARA contexts)
            def _behavioral_signal_count(vec: Dict[str, float]) -> int:
                cnt = 0
                for k, v in vec.items():
                    if k.startswith("yara_"):
                        continue
                    if k in ("yara_match",):
                        continue
                    try:
                        if float(v) != 0.0:
                            cnt += 1
                    except Exception:
                        continue
                return cnt

            behavioral_signal_count = _behavioral_signal_count(feature_vector)

            # Context-aware YARA boosting with corroboration rule
            # Low-trust contexts cannot elevate threat tier alone.
            LOW_TRUST = {"ADS_METADATA", "UNKNOWN"}
            min_behavioral_signals = 2

            if yara_matched:
                yara_escalation_allowed = True
                if yara_context in LOW_TRUST and behavioral_signal_count < min_behavioral_signals:
                    yara_escalation_allowed = False
                    yara_downweight_reason = (
                        f"low_trust_context_{yara_context.lower()}_insufficient_behavioral_signals_"
                        f"{behavioral_signal_count}<{min_behavioral_signals}"
                    )

                # Base YARA score derived from confidence (preserves capability) then weighted by context
                def _base_yara_score(conf: float) -> float:
                    if conf >= 0.95:
                        return 50.0
                    if conf >= 0.90:
                        return 35.0
                    if conf >= 0.85:
                        return 25.0
                    if conf >= 0.75:
                        return 20.0
                    if conf >= 0.60:
                        return 10.0
                    return 5.0

                if yara_escalation_allowed:
                    yara_boost = _base_yara_score(yara_raw_confidence) * float(yara_context_weight)
                else:
                    yara_boost = 0.0

            score = max(0.0, min(100.0, float(base_score) + float(yara_boost)))
            
            # Determine tier
            tier = RiskTier(self.ml_scorer.get_tier(score))
            
            # Update statistics
            with self._lock:
                self.tier_distribution[tier.value] += 1
            
            # Build genealogy tree for visualization (NOT used for ML scoring)
            genealogy_tree = self.genealogy_builder.build_genealogy(pid)
            genealogy_data = None
            if genealogy_tree:
                genealogy_data = {
                    "root_pid": genealogy_tree.root_pid,
                    "tree_depth": genealogy_tree.tree_depth,
                    "tree_width": genealogy_tree.tree_width,
                    "total_descendants": genealogy_tree.total_descendants,
                    "ancestors": genealogy_tree.ancestors,
                    "descendants": genealogy_tree.descendants,
                    "full_tree": genealogy_tree.full_tree
                }
            
            # Annotate event with Stage 3 results
            event['__stage3'] = True
            event['__stage3_score'] = score
            event['__stage3_tier'] = tier.value
            event['__stage3_features'] = feature_vector
            event['__stage3_timestamp'] = time.time()
            event['__stage3_yara_matched'] = yara_matched
            event['__stage3_yara_rules'] = yara_rules
            event['__stage3_yara_confidence'] = yara_raw_confidence

            # Context-aware YARA telemetry (for dashboard transparency)
            event['__stage3_yara_context'] = yara_context
            event['__stage3_yara_context_weight'] = yara_context_weight
            event['__stage3_yara_weighted_confidence'] = yara_weighted_confidence
            event['__stage3_yara_boost'] = yara_boost
            event['__stage3_yara_escalation_allowed'] = yara_escalation_allowed
            event['__stage3_behavioral_signal_count'] = behavioral_signal_count
            if yara_downweight_reason:
                event['__stage3_yara_downweight_reason'] = yara_downweight_reason
            
            # Add diagnostics for better visibility
            if diagnostics:
                event['__stage3_data_quality'] = diagnostics.get("data_quality", "unknown")
                event['__stage3_feature_diagnostics'] = diagnostics
                
                # Log warning if data quality is poor
                if diagnostics.get("data_quality") == "insufficient":
                    logger.warning(
                        f"Stage3: PID {pid} scored with insufficient data. "
                        f"Quality: {diagnostics.get('data_quality')}, "
                        f"Events: {diagnostics.get('events_seen', 0)}, "
                        f"Types: {diagnostics.get('event_types_seen', [])}"
                    )
            
            # Add genealogy data for dashboard visualization (NOT used for ML scoring)
            if genealogy_data:
                event['__stage3_genealogy'] = genealogy_data
            
            # Tiered decision logic
            promoted_to_stage4 = False
            immediate_response_triggered = False
            reason = ""
            
            if tier == RiskTier.LOW:
                # 0-59: Clearly benign - log silently, ignore
                with self._lock:
                    self.total_dropped += 1
                reason = "low_risk_benign"
                logger.debug(f"Stage3 LOW: PID={pid} Score={score:.2f} - dropped")
                
            elif tier == RiskTier.MEDIUM:
                # 60-79: Possible threat - forward to Stage 4 for deep analysis
                with self._lock:
                    self.total_promoted_to_stage4 += 1
                promoted_to_stage4 = True
                reason = "medium_suspicious_needs_confirmation"
                
                if self.stage4_callback:
                    try:
                        self.stage4_callback(event)
                    except Exception:
                        logger.exception(f"Stage4 callback failed for PID {pid}")
                
                logger.warning(
                    f"Stage3 MEDIUM → Stage4: PID={pid} Score={score:.2f} "
                    f"(YARA={'matched' if yara_matched else 'no match'})"
                )
                
            elif tier == RiskTier.HIGH:
                # 80-94: Strong ransomware signal with confidence-band split
                # - high_low (80-87): immediate containment + Stage4 confirmation
                # - high_high (88-94): immediate containment only
                high_band = "high_low" if score <= self.high_band_split_score else "high_high"
                event['__stage3_high_band'] = high_band
                event['__stage3_high_band_split'] = self.high_band_split_score

                with self._lock:
                    self.total_immediate_responses += 1
                immediate_response_triggered = True
                reason = f"high_risk_{high_band}_immediate_response"
                
                # Trigger immediate response (kill process, isolate, block network, VSS snapshot)
                if self.immediate_response_callback:
                    try:
                        self.immediate_response_callback(event, tier, score)
                    except Exception:
                        logger.exception(f"Immediate response callback failed for PID {pid}")

                # For lower confidence high band, still request Stage 4 confirmation.
                if high_band == "high_low" and self.stage4_callback:
                    with self._lock:
                        self.total_promoted_to_stage4 += 1
                    promoted_to_stage4 = True
                    try:
                        self.stage4_callback(event)
                    except Exception:
                        logger.exception(f"Stage4 callback failed for PID {pid}")

                logger.error(
                    f"Stage3 HIGH ({high_band}): PID={pid} Score={score:.2f} - "
                    f"IMMEDIATE RESPONSE TRIGGERED (YARA={'matched' if yara_matched else 'no match'})"
                )
                
            elif tier == RiskTier.CRITICAL:
                # 95-100: Near-certain ransomware - nuclear response + Stage 4 forensics
                with self._lock:
                    self.total_immediate_responses += 1
                    self.total_promoted_to_stage4 += 1
                immediate_response_triggered = True
                promoted_to_stage4 = True
                reason = "critical_risk_nuclear_response"
                
                # Trigger nuclear response (full kill/suspend/quarantine + memory dump + isolation)
                if self.immediate_response_callback:
                    try:
                        self.immediate_response_callback(event, tier, score)
                    except Exception:
                        logger.exception(f"Immediate response callback failed for PID {pid}")
                
                # Always forward to Stage 4 for full forensics
                if self.stage4_callback:
                    try:
                        self.stage4_callback(event)
                    except Exception:
                        logger.exception(f"Stage4 callback failed for PID {pid}")
                
                logger.critical(
                    f"Stage3 CRITICAL: PID={pid} Score={score:.2f} - NUCLEAR RESPONSE + Stage4 "
                    f"(YARA={'matched' if yara_matched else 'no match'})"
                )
            
            return Stage3Result(
                tier=tier,
                score=score,
                yara_matched=yara_matched,
                yara_rules=yara_rules,
                promoted_to_stage4=promoted_to_stage4,
                immediate_response_triggered=immediate_response_triggered,
                reason=reason
            )
                
        except Exception:
            logger.exception(f"Error processing event in Stage3: {event.get('EventID', 'unknown')}")
            return Stage3Result(
                tier=RiskTier.LOW,
                score=0.0,
                yara_matched=False,
                yara_rules=[],
                promoted_to_stage4=False,
                immediate_response_triggered=False,
                reason="processing_error"
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get Stage 3 metrics"""
        with self._lock:
            return {
                'total_processed': self.total_processed,
                'total_promoted_to_stage4': self.total_promoted_to_stage4,
                'total_dropped': self.total_dropped,
                'total_immediate_responses': self.total_immediate_responses,
                'promotion_rate': (
                    self.total_promoted_to_stage4 / max(1, self.total_processed) * 100
                ),
                'immediate_response_rate': (
                    self.total_immediate_responses / max(1, self.total_processed) * 100
                ),
                'tier_distribution': self.tier_distribution.copy(),
                'threshold': self.ml_scorer.get_threshold(),
                'tracked_processes': self.feature_extractor.get_process_count(),
                'yara_available': self.yara_scanner.is_available()
            }
    
    def cleanup(self) -> None:
        """Cleanup old processes (manual trigger - background thread handles automatic cleanup)"""
        self.feature_extractor.cleanup_old_processes()
        self.genealogy_builder.cleanup_old_processes()
    
    def shutdown(self) -> None:
        """Shutdown Stage 3 engine and stop background threads"""
        self.feature_extractor.stop_cleanup_thread()
        logger.info("Stage3Engine shutdown complete")
    
    def set_threshold(self, threshold: float) -> None:
        """Update ML score threshold"""
        self.ml_scorer.set_threshold(threshold)
        logger.info(f"Stage3 threshold updated to {threshold}")


# Global engine instance
_ENGINE: Optional[Stage3Engine] = None


def get_stage3_engine() -> Optional[Stage3Engine]:
    """Get global Stage 3 engine instance"""
    return _ENGINE


def initialize_stage3(
    model_path: Optional[str] = None,
    threshold: float = 50.0,
    tier_low_max: float = 59.0,
    tier_medium_max: float = 79.0,
    tier_high_max: float = 94.0,
    high_band_split_score: float = 87.0,
    stage4_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    yara_rules_path: Optional[str] = None,
    immediate_response_callback: Optional[Callable[[Dict[str, Any], RiskTier, float], None]] = None,
    **kwargs
) -> Stage3Engine:
    """
    Initialize global Stage 3 engine with YARA and tiered thresholds.
    
    Args:
        model_path: Path to LightGBM model file
        threshold: Legacy ML score threshold (0-100) - kept for compatibility
        tier_low_max: Upper bound for LOW tier
        tier_medium_max: Upper bound for MEDIUM tier
        tier_high_max: Upper bound for HIGH tier
        high_band_split_score: Split score for HIGH band policy
        stage4_callback: Callback for Stage 4 events (Medium/Critical tiers)
        yara_rules_path: Path to YARA rules file or directory
        immediate_response_callback: Callback for High/Critical tiers requiring immediate response
        **kwargs: Additional arguments for Stage3Engine
        
    Returns:
        Initialized Stage3Engine instance
    """
    global _ENGINE
    _ENGINE = Stage3Engine(
        model_path=model_path,
        threshold=threshold,
        tier_low_max=tier_low_max,
        tier_medium_max=tier_medium_max,
        tier_high_max=tier_high_max,
        high_band_split_score=high_band_split_score,
        stage4_callback=stage4_callback,
        yara_rules_path=yara_rules_path,
        immediate_response_callback=immediate_response_callback,
        **kwargs
    )
    logger.info("Global Stage3Engine initialized with YARA and tiered thresholds")
    return _ENGINE

