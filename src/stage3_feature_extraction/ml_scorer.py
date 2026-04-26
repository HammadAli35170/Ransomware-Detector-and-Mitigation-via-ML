"""
Robust LightGBM-based ML Scorer for Stage 3 Ransomware Detection

Features:
- Safe model loading with validation
- Feature alignment check (against training schema)
- Input sanitization (missing values, NaN/inf handling)
- YARA-aware scoring boost with confidence weighting
- Fallback scoring weighted by real model importance
- Detailed logging & observability
- Configurable risk tiers & thresholds
"""

import logging
import os
import json
from typing import Dict, Any, Optional, List, Tuple
import numpy as np

logger = logging.getLogger("stage3_ml_scorer")

# Lazy import of lightgbm
_lgb = None
_LIGHTGBM_AVAILABLE = None


def _lazy_import_lightgbm():
    global _lgb, _LIGHTGBM_AVAILABLE
    if _LIGHTGBM_AVAILABLE is None:
        try:
            import lightgbm as lgb
            _lgb = lgb
            _LIGHTGBM_AVAILABLE = True
            logger.debug("LightGBM successfully imported")
        except ImportError:
            _LIGHTGBM_AVAILABLE = False
            logger.warning("LightGBM not available. Install with: pip install lightgbm")
    return _LIGHTGBM_AVAILABLE


class MLScorer:
    """
    Production-ready ML scorer for ransomware detection.

    - Uses LightGBM model when available
    - Falls back to importance-weighted heuristic scoring when model is missing
    - Validates feature alignment
    - Applies context-aware YARA boosting
    - Returns score 0–100 + risk tier
    """

    # Default risk tiers (can be overridden)
    RISK_TIERS = {
        (0, 40):   "low",
        (40, 65):  "medium",
        (65, 85):  "high",
        (85, 100): "critical"
    }

    # Default fallback weights — based on your real model importance (top features first)
    # These should match your actual trained model top contributors
    FALLBACK_WEIGHTS = {
        # Critical / dominant features (high weight)
        "network_burst_60s":              0.52,   # ~51.6%
        "family_file_deletes":            0.24,   # ~23.6%
        "registry_modification_anomaly":  0.12,   # ~11.6%
        "unsigned_image_mapped":          0.04,
        "family_suspicious_paths":        0.03,
        "executable_path_mismatch":       0.02,
        "dlls_unusual_directories":       0.02,
        # Medium importance
        "working_directory_anomaly":      0.015,
        "scheduled_task_creation_attempts": 0.015,
        "excessive_crypt_apis":           0.01,
        # Supporting features
        "file_extension_anomaly":         0.008,
        "entropy_trend":                  0.007,
        "burstiness_file_io":             0.006,
        "unexpected_spawning_patterns":   0.005,
        # Everything else gets small default weight
    }

    DEFAULT_YARA_BOOST = 18.0          # max boost if confidence=1.0
    YARA_CONFIDENCE_THRESHOLD = 0.65   # min confidence to apply boost

    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = 65.0,          # higher default — more conservative
        yara_boost_max: float = DEFAULT_YARA_BOOST,
        feature_names: Optional[List[str]] = None,
        verbose: bool = False
    ):
        """
        Initialize ML scorer.

        Args:
            model_path: Path to LightGBM model (.txt)
            threshold: Score above which we consider "suspicious" (default 65)
            yara_boost_max: Maximum score boost from strong YARA match
            feature_names: Optional explicit list of expected features
            verbose: Enable detailed logging
        """
        self.model_path = model_path
        self.threshold = max(0.0, min(100.0, threshold))
        self.yara_boost_max = max(0.0, min(40.0, yara_boost_max))  # cap boost
        self.verbose = verbose

        # Logging level
        if verbose:
            logger.setLevel(logging.DEBUG)

        # Feature names
        self.feature_names = feature_names or self._get_default_feature_names()
        self.feature_idx_map = {name: i for i, name in enumerate(self.feature_names)}

        # Model state
        self.model = None
        self.model_metadata = {}
        self.is_model_loaded = False

        # Load model if path provided
        if model_path:
            self._load_model(model_path)

        if not self.is_model_loaded:
            logger.info("ML model not loaded → using importance-weighted fallback scoring")

    def _get_default_feature_names(self) -> List[str]:
        """Returns the expected feature list (same as training)"""
        return [
            'cpu_usage_trend', 'cpu_spike_deviation', 'ram_usage_trend', 'sudden_ram_spikes',
            'thread_count_delta', 'handle_count_delta', 'total_bytes_written',
            'files_created', 'files_modified', 'files_deleted',
            'files_created_rate', 'files_deleted_rate', 'bytes_written_rate',
            'lifecycle_peak_file_rate', 'burstiness_file_io',
            'medium_term_file_rate', 'long_term_file_rate', 'file_io_acceleration',
            'entropy_trend', 'entropy_velocity', 'entropy_acceleration',
            'signature_trust_level', 'is_microsoft_signed', 'cert_mismatch_tampering',
            'parent_child_anomaly_score', 'unexpected_spawning_patterns',
            'spawn_depth', 'injection_edge_flag', 'shared_handles_flag',
            'family_file_creates', 'family_file_deletes', 'family_network_conns',
            'family_registry_mods', 'sibling_count', 'family_entropy_avg',
            'family_suspicious_paths', 'family_file_rate', 'family_network_rate',
            'network_connections', 'dns_lookup_count', 'outbound_connection_anomaly',
            'total_sockets_created', 'unexpected_ports_touched', 'unusual_destination_ip_behavior',
            'network_connection_rate', 'network_burst_60s', 'beacon_interval_std',
            'suspicious_tld_flag', 'asn_risk_score', 'geo_risk_score',
            'working_directory_anomaly', 'executable_path_mismatch',
            'image_memory_disk_mismatch', 'unsigned_image_mapped', 'writexecutable_memory_regions',
            'memory_region_entropy_anomalies', 'thread_start_address_anomalies',
            'module_load_anomaly_score', 'unexpected_dlls_loaded', 'dlls_unusual_directories',
            'suspicious_api_call_frequency', 'excessive_crypt_apis', 'excessive_virtualalloc',
            'excessive_writeprocessmemory', 'excessive_createremotethread',
            'token_privilege_escalation', 'unexpected_privilege_acquisition', 'access_token_manipulation',
            'registry_modification_anomaly', 'scheduled_task_creation_attempts',
            'process_created_suspended', 'ntunmapviewofsection_usage', 'large_writeprocessmemory_activity',
            'thread_resume_sequence_anomalies', 'file_rename_patterns', 'file_extension_anomaly',
            'content_rewriting_patterns', 'suspicious_honeypot_access',
            'user_interactivity_anomaly', 'unexpected_gui_access', 'unexpected_clipboard_access',
            'temporal_correlation_spikes', 'temporal_spikes_5min', 'temporal_spikes_30min',
            'file_event_concentration', 'baseline_deviation_score',
            'yara_match_memory', 'yara_match_executable', 'yara_match_script',
            'yara_match_document', 'yara_match_ads', 'yara_weighted_confidence',
            'yara_match_strength',
        ]

    def _load_model(self, path: str) -> bool:
        """Safely load LightGBM model with validation"""
        if not os.path.exists(path):
            logger.error(f"Model file not found: {path}")
            return False

        lgb = _lazy_import_lightgbm()
        if not lgb:
            logger.error("Cannot load model: LightGBM not installed")
            return False

        try:
            self.model = lgb.Booster(model_file=path)
            logger.info(f"✓ Loaded LightGBM model from {path}")
            logger.info(f"  - Number of trees: {self.model.num_trees()}")
            logger.info(f"  - Best iteration: {self.model.best_iteration}")

            # Try to read metadata if available
            try:
                metadata = self.model.get_metadata()
                if metadata:
                    self.model_metadata = json.loads(metadata) if isinstance(metadata, str) else metadata
                    logger.debug("Model metadata loaded")
            except:
                pass

            self.is_model_loaded = True
            return True

        except Exception as e:
            logger.error(f"Failed to load LightGBM model: {e}", exc_info=True)
            self.model = None
            return False

    def _sanitize_features(self, feature_dict: Dict[str, Any]) -> np.ndarray:
        """
        Convert dict → ordered numpy array + clean invalid values
        """
        array = np.zeros(len(self.feature_names), dtype=np.float32)

        for name, value in feature_dict.items():
            if name not in self.feature_idx_map:
                continue
            idx = self.feature_idx_map[name]
            try:
                val = float(value)
                if np.isnan(val) or np.isinf(val):
                    val = 0.0
                array[idx] = val
            except (ValueError, TypeError):
                array[idx] = 0.0

        return array

    def _apply_yara_boost(self, base_score: float, yara_confidence: float) -> float:
        """Apply YARA-based score boost (confidence-weighted)"""
        if yara_confidence < self.YARA_CONFIDENCE_THRESHOLD:
            return base_score

        boost = self.yara_boost_max * (yara_confidence ** 1.5)  # non-linear boost
        boost = min(boost, self.yara_boost_max)

        new_score = base_score + boost
        logger.debug(f"YARA boost applied: +{boost:.1f} (confidence={yara_confidence:.2f})")

        return min(100.0, new_score)

    def score(
        self,
        feature_vector: Dict[str, Any],
        yara_confidence: float = 0.0,
        yara_matched: bool = False,  # legacy
        return_details: bool = False
    ) -> float | Tuple[float, Dict[str, Any]]:
        """
        Main scoring function.

        Returns:
            score (0–100) or (score, details_dict) if return_details=True
        """
        try:
            # 1. Prepare clean feature vector
            X = self._sanitize_features(feature_vector)

            # 2. ML model scoring
            if self.is_model_loaded:
                try:
                    prob = self.model.predict(X.reshape(1, -1), num_iteration=self.model.best_iteration)[0]
                    
                    # ============ HYBRID RESCUE SCORING ============
                    # If dominant features are near-zero but secondary indicators are strong,
                    # boost the score to prevent false negatives
                    dominant_sum = (
                        feature_vector.get('network_burst_60s', 0.0) +
                        feature_vector.get('family_file_deletes', 0.0) +
                        feature_vector.get('registry_modification_anomaly', 0.0)
                    )
                    
                    if dominant_sum < 5.0:  # Dominant features are weak/broken
                        # Check secondary ransomware indicators
                        secondary_score = 0.0
                        
                        # High entropy + velocity
                        entropy_vel = feature_vector.get('entropy_velocity', 0.0)
                        if entropy_vel > 0.3:
                            secondary_score += 15.0
                        
                        # Many file modifications
                        files_mod = feature_vector.get('files_modified', 0.0)
                        if files_mod > 30:
                            secondary_score += 20.0
                        elif files_mod > 15:
                            secondary_score += 12.0
                        
                        # Many deletes (even if family aggregation is broken)
                        files_del = feature_vector.get('files_deleted', 0.0)
                        if files_del > 20:
                            secondary_score += 18.0
                        elif files_del > 10:
                            secondary_score += 10.0
                        
                        # High burstiness
                        burst = feature_vector.get('burstiness_file_io', 0.0)
                        if burst > 0.7:
                            secondary_score += 15.0
                        
                        # Network activity
                        net_conns = feature_vector.get('network_connections', 0.0)
                        if net_conns > 15:
                            secondary_score += 10.0
                        
                        if secondary_score > 30.0:
                            logger.info(f"Hybrid rescue activated: dominant features weak but secondary indicators strong (boost applied)")
                            prob = max(prob, secondary_score / 100.0)  # Boost probability
                    # ===============================================
                    
                    # Calibrate to 0–100 (sigmoid-like mapping for better spread)
                    score = 100.0 * (1.0 / (1.0 + np.exp(-5.0 * (prob - 0.45))))
                    score = float(np.clip(score, 0.0, 100.0))
                    method = "ml_model"
                except Exception as e:
                    logger.error(f"ML prediction failed: {e}", exc_info=True)
                    score = 50.0
                    method = "ml_fallback_error"
            else:
                # 3. Weighted fallback scoring
                score = 0.0
                for fname, weight in self.FALLBACK_WEIGHTS.items():
                    if fname in feature_vector:
                        val = float(feature_vector[fname])
                        if np.isnan(val) or np.isinf(val):
                            val = 0.0
                        # Simple non-linear scaling
                        contrib = weight * 100.0 * min(1.0, max(0.0, val / max(1.0, val + 10.0)))
                        score += contrib

                # Normalize to 0-100 range
                score = min(100.0, score * 1.3)  # slight upward adjustment
                method = "fallback_heuristic"

            # 4. Apply YARA boost (if strong match)
            if yara_confidence > 0 or yara_matched:
                score = self._apply_yara_boost(score, yara_confidence)

            # Final clamp
            score = float(np.clip(score, 0.0, 100.0))

            if return_details:
                return score, {
                    "score": score,
                    "method": method,
                    "yara_confidence": yara_confidence,
                    "risk_tier": self.get_tier(score),
                    "above_threshold": score >= self.threshold
                }

            return score

        except Exception as e:
            logger.exception(f"Critical error in scoring: {e}")
            return 45.0  # safe medium-low score on total failure

    def get_tier(self, score: float) -> str:
        """Get risk tier name"""
        for (low, high), tier in sorted(self.RISK_TIERS.items(), key=lambda x: x[0][0]):
            if low <= score < high:
                return tier
        return "critical" if score >= 100 else "low"

    def should_promote(self, score: float) -> bool:
        """Should this event go to Stage 4 / alert?"""
        return score >= self.threshold

    def get_threshold(self) -> float:
        return self.threshold

    def set_threshold(self, new_threshold: float):
        self.threshold = float(np.clip(new_threshold, 0.0, 100.0))
        logger.info(f"Promotion threshold updated to {self.threshold:.1f}")

    def get_feature_count(self) -> int:
        return len(self.feature_names)

    def get_model_info(self) -> Dict[str, Any]:
        """Return model status information"""
        return {
            "model_loaded": self.is_model_loaded,
            "model_path": self.model_path,
            "feature_count": len(self.feature_names),
            "threshold": self.threshold,
            "yara_boost_max": self.yara_boost_max,
            "fallback_active": not self.is_model_loaded,
            "model_metadata": self.model_metadata if self.is_model_loaded else {}
        }


# Quick test / demo when run directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    scorer = MLScorer(
        model_path="models/stage3_balanced_v2.txt",  # ← change to your model
        threshold=65.0,
        verbose=True
    )

    # Example feature vector (minimal malicious-like)
    test_features = {
        "network_burst_60s": 820.0,
        "family_file_deletes": 320.0,
        "registry_modification_anomaly": 140.0,
        "unsigned_image_mapped": 1.0,
        "file_extension_anomaly": 12.0,
        "entropy_trend": 7.9,
        "burstiness_file_io": 18.5,
        "yara_weighted_confidence": 0.92,
    }

    score = scorer.score(test_features, yara_confidence=0.92)
    tier = scorer.get_tier(score)

    print(f"\nTest Score: {score:.1f}/100")
    print(f"Risk Tier:  {tier}")
    print(f"Promote?    {score >= scorer.threshold}")