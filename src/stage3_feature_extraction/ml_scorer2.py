"""
LightGBM-based Fast ML Scorer for Stage 3

Provides real-time scoring (0-100) using a trained LightGBM model.
Falls back to comprehensive static/rule-based scorer when ML model is not available.
The static scorer evaluates all 51 features and provides accurate scoring for testing.
"""

import logging
import os
from typing import Dict, Any, Optional
import numpy as np

logger = logging.getLogger("stage3_ml_scorer")

# Lazy import: lightgbm will only be imported when actually needed (when loading a model)
# This avoids the slow scipy import chain at startup
_lgb = None
_LIGHTGBM_AVAILABLE = None


def _check_lightgbm_available() -> bool:
    """Lazily check if lightgbm is available (only when needed)"""
    global _lgb, _LIGHTGBM_AVAILABLE
    if _LIGHTGBM_AVAILABLE is None:
        try:
            import lightgbm as lgb
            _lgb = lgb
            _LIGHTGBM_AVAILABLE = True
            logger.debug("LightGBM imported successfully")
        except ImportError as e:
            _LIGHTGBM_AVAILABLE = False
            logger.warning(f"LightGBM not available: {e}. Install with: pip install lightgbm")
    return _LIGHTGBM_AVAILABLE


def _get_lightgbm():
    """Get lightgbm module (lazy import)"""
    if _check_lightgbm_available():
        return _lgb
    return None


class MLScorer:
    """
    LightGBM-based ML scorer for ransomware detection.
    
    Scores feature vectors on a scale of 0-100, where:
    - 0-30: Low risk
    - 30-60: Medium risk
    - 60-80: High risk
    - 80-100: Critical risk
    """
    
    # Expected feature names (must match feature_extractor output).
    # Note: YARA is represented as context-aware features (not a single binary flag).
    EXPECTED_FEATURES = [
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
        'family_file_creates', 'family_file_deletes', 'family_network_conns', 'family_registry_mods',
        'sibling_count', 'family_entropy_avg', 'family_suspicious_paths', 'family_file_rate', 'family_network_rate',
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
        # Context-aware YARA features (Stage 3 sets these)
        'yara_match_memory',
        'yara_match_executable',
        'yara_match_script',
        'yara_match_document',
        'yara_match_ads',
        'yara_weighted_confidence',
        'yara_match_strength',
    ]
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = 50.0,
        tier_low_max: float = 59.0,
        tier_medium_max: float = 79.0,
        tier_high_max: float = 94.0,
    ):
        """
        Initialize ML scorer.
        
        Args:
            model_path: Path to trained LightGBM model file (.txt or .pkl)
                       If None, uses a default/fallback scoring method
            threshold: Score threshold for promotion to Stage 4 (default 50.0)
        """
        self.model_path = model_path
        self.threshold = threshold
        self.model: Optional[Any] = None
        self.feature_names = self.EXPECTED_FEATURES.copy()
        self.tier_low_max = float(tier_low_max)
        self.tier_medium_max = float(tier_medium_max)
        self.tier_high_max = float(tier_high_max)

        # Ensure tier boundaries are strictly ordered. Fall back to defaults if invalid.
        if not (0.0 <= self.tier_low_max < self.tier_medium_max < self.tier_high_max <= 100.0):
            logger.warning(
                "Invalid Stage3 tier boundaries (low=%s, medium=%s, high=%s). "
                "Falling back to defaults 59/79/94.",
                self.tier_low_max,
                self.tier_medium_max,
                self.tier_high_max,
            )
            self.tier_low_max = 59.0
            self.tier_medium_max = 79.0
            self.tier_high_max = 94.0
        
        # Only attempt to load model if model_path is provided
        # This avoids importing lightgbm/scipy at startup if no model is needed
        # When model_path is provided, lightgbm will be imported lazily at this point
        if model_path and os.path.exists(model_path):
            logger.info(f"Model file provided: {model_path}. Attempting to load LightGBM model...")
            # Lazy import: only import lightgbm when actually loading a model
            # This happens here when model_path is provided, not at module import time
            lgb = _get_lightgbm()
            if lgb is None:
                logger.warning("LightGBM not available. Cannot load ML model. Using static/rule-based scorer.")
                logger.warning("To use ML model, install LightGBM: pip install lightgbm")
                self.model = None
            else:
                try:
                    # Import lightgbm succeeded - now load the model
                    self.model = lgb.Booster(model_file=model_path)
                    logger.info(f"✓ Successfully loaded LightGBM model from {model_path}")
                    logger.info("ML scoring will be used for Stage 3 (with static scorer as fallback)")
                except Exception as e:
                    logger.error(f"Failed to load model from {model_path}: {e}")
                    logger.info("Falling back to static/rule-based scorer.")
                    self.model = None
        elif model_path:
            # Model path provided but file doesn't exist
            logger.warning(f"Model file specified but not found: {model_path}")
            logger.info("Using static/rule-based scorer (comprehensive fallback).")
            self.model = None
        else:
            # No model path provided - use static scorer (fast startup, no lightgbm import)
            logger.info("No model file provided. Using static/rule-based scorer (comprehensive fallback).")
            logger.info("Static scorer evaluates all 51 features for accurate testing without ML model.")
            logger.info("To use ML model, provide model_path when initializing MLScorer.")
            self.model = None
    
    def score(self, feature_vector: Dict[str, float], yara_matched: bool = False, yara_confidence: float = 0.0) -> float:
        """
        Score a feature vector and return risk score (0-100).
        
        Args:
            feature_vector: Dictionary of feature names to values
            yara_matched: Whether YARA scan matched (for auto-bump)
            yara_confidence: YARA match confidence (0.0-1.0)
            
        Returns:
            Risk score from 0-100
        """
        try:
            # Convert feature vector to array in correct order
            feature_array = self._vector_to_array(feature_vector)
            
            if self.model is not None:
                # Use LightGBM model
                prediction = self.model.predict(feature_array.reshape(1, -1), num_iteration=self.model.best_iteration)[0]
                # Convert to 0-100 scale (assuming model outputs 0-1 probability)
                score = float(prediction * 100.0)
                # Clamp to 0-100
                score = max(0.0, min(100.0, score))
                logger.debug("ML model scoring used")
            else:
                # Fallback: Comprehensive static/rule-based scoring
                # This allows testing Stage 3 without ML model
                score = self._fallback_score(feature_vector)
                logger.debug("Static scorer used (ML model not available)")
            
            # NOTE: YARA score bumping is handled in Stage3Engine with context-aware weighting
            # and corroboration rules. We keep yara_matched/yara_confidence in the signature for
            # backwards compatibility but do not apply any boost here.
            return score
            
        except Exception as e:
            logger.exception(f"Error scoring feature vector: {e}")
            # Return medium risk on error
            return 50.0
    
    def _vector_to_array(self, feature_vector: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to numpy array in expected order"""
        array = []
        for feature_name in self.feature_names:
            value = feature_vector.get(feature_name, 0.0)
            try:
                array.append(float(value))
            except (ValueError, TypeError):
                array.append(0.0)
        return np.array(array, dtype=np.float32)
    
    def _fallback_score(self, feature_vector: Dict[str, float]) -> float:
        """
        Comprehensive static/rule-based scorer when ML model is not available.
        
        This is a sophisticated heuristic-based approach that evaluates all 51 features
        to provide accurate scoring for testing Stage 3 without ML model.
        
        Scoring weights are based on ransomware behavior patterns:
        - Critical indicators (honeypot, YARA): High weight
        - Strong indicators (entropy, file patterns): Medium-high weight
        - Moderate indicators (network, memory): Medium weight
        - Weak indicators (path anomalies): Low weight
        """
        score = 0.0
        
        # ========== CRITICAL INDICATORS (High Weight) ==========
        
        # Honeypot access (strongest indicator)
        if feature_vector.get('suspicious_honeypot_access', 0) > 0:
            score += 35.0
            logger.debug("Static scorer: Honeypot access detected (+35)")
        
        # YARA is handled in Stage3Engine (context-aware weighting + corroboration). Do not
        # double-count it here.
        
        # Certificate tampering
        if feature_vector.get('cert_mismatch_tampering', 0) > 0:
            score += 18.0
        if feature_vector.get('is_microsoft_signed', 0) == 0:
            score += 8.0  # Unsigned binary
        
        # ========== STRONG INDICATORS (Medium-High Weight) ==========
        
        # Entropy (encryption indicator)
        entropy_trend = feature_vector.get('entropy_trend', 0)
        if entropy_trend > 7.8:
            score += 20.0
        elif entropy_trend > 7.5:
            score += 15.0
        elif entropy_trend > 7.0:
            score += 10.0
        
        entropy_velocity = feature_vector.get('entropy_velocity', 0)
        if entropy_velocity > 0.5:
            score += 12.0
        elif entropy_velocity > 0.3:
            score += 8.0
        
        # File I/O patterns (ransomware signature)
        files_modified = feature_vector.get('files_modified', 0)
        if files_modified > 100:
            score += 25.0
        elif files_modified > 50:
            score += 18.0
        elif files_modified > 25:
            score += 12.0
        
        files_deleted = feature_vector.get('files_deleted', 0)
        if files_deleted > 20:
            score += 15.0
        elif files_deleted > 10:
            score += 10.0
        
        # Burstiness (rapid file operations)
        burstiness = feature_vector.get('burstiness_file_io', 0)
        if burstiness > 15.0:
            score += 18.0
        elif burstiness > 10.0:
            score += 12.0
        elif burstiness > 5.0:
            score += 8.0
        
        # File patterns (ransomware behavior)
        file_rename_patterns = feature_vector.get('file_rename_patterns', 0)
        if file_rename_patterns > 20:
            score += 15.0
        elif file_rename_patterns > 10:
            score += 10.0
        
        file_extension_anomaly = feature_vector.get('file_extension_anomaly', 0)
        if file_extension_anomaly > 10:
            score += 12.0
        elif file_extension_anomaly > 5:
            score += 8.0
        
        content_rewriting = feature_vector.get('content_rewriting_patterns', 0)
        if content_rewriting > 5:
            score += 10.0
        
        # ========== MODERATE INDICATORS (Medium Weight) ==========
        
        # Process hollowing/injection (malware technique)
        if feature_vector.get('process_created_suspended', 0) > 0:
            score += 16.0
        if feature_vector.get('ntunmapviewofsection_usage', 0) > 0:
            score += 14.0
        if feature_vector.get('large_writeprocessmemory_activity', 0) > 0:
            score += 12.0
        if feature_vector.get('thread_resume_sequence_anomalies', 0) > 0:
            score += 10.0
        
        # Memory anomalies
        if feature_vector.get('writexecutable_memory_regions', 0) > 0:
            score += 14.0
        if feature_vector.get('unsigned_image_mapped', 0) > 0:
            score += 12.0
        if feature_vector.get('image_memory_disk_mismatch', 0) > 0:
            score += 10.0
        if feature_vector.get('memory_region_entropy_anomalies', 0) > 0:
            score += 10.0
        if feature_vector.get('thread_start_address_anomalies', 0) > 0:
            score += 8.0
        
        # API abuse
        excessive_crypt = feature_vector.get('excessive_crypt_apis', 0)
        if excessive_crypt > 10:
            score += 15.0
        elif excessive_crypt > 5:
            score += 10.0
        
        if feature_vector.get('excessive_virtualalloc', 0) > 5:
            score += 10.0
        if feature_vector.get('excessive_writeprocessmemory', 0) > 5:
            score += 12.0
        if feature_vector.get('excessive_createremotethread', 0) > 3:
            score += 12.0
        
        suspicious_api = feature_vector.get('suspicious_api_call_frequency', 0)
        if suspicious_api > 20:
            score += 10.0
        elif suspicious_api > 10:
            score += 7.0
        
        # Privilege escalation
        if feature_vector.get('token_privilege_escalation', 0) > 0:
            score += 12.0
        if feature_vector.get('unexpected_privilege_acquisition', 0) > 0:
            score += 10.0
        if feature_vector.get('access_token_manipulation', 0) > 0:
            score += 10.0
        
        # ========== MODERATE-LOW INDICATORS ==========
        
        # Network anomalies
        if feature_vector.get('unusual_destination_ip_behavior', 0) > 0:
            score += 10.0
        unexpected_ports = feature_vector.get('unexpected_ports_touched', 0)
        if unexpected_ports > 10:
            score += 10.0
        elif unexpected_ports > 5:
            score += 7.0
        
        outbound_anomaly = feature_vector.get('outbound_connection_anomaly', 0)
        if outbound_anomaly > 0.5:
            score += 8.0
        
        # Process tree anomalies
        parent_anomaly = feature_vector.get('parent_child_anomaly_score', 0)
        if parent_anomaly > 5:
            score += 10.0
        elif parent_anomaly > 2:
            score += 6.0
        
        if feature_vector.get('unexpected_spawning_patterns', 0) > 0:
            score += 8.0
        
        # DLL/Module anomalies
        dll_anomaly = feature_vector.get('module_load_anomaly_score', 0)
        if dll_anomaly > 5:
            score += 8.0
        
        unexpected_dlls = feature_vector.get('unexpected_dlls_loaded', 0)
        if unexpected_dlls > 5:
            score += 7.0
        elif unexpected_dlls > 2:
            score += 4.0
        
        if feature_vector.get('dlls_unusual_directories', 0) > 0:
            score += 6.0
        
        # Registry anomalies
        if feature_vector.get('registry_modification_anomaly', 0) > 0:
            score += 8.0
        if feature_vector.get('scheduled_task_creation_attempts', 0) > 0:
            score += 10.0
        
        # ========== LOW INDICATORS (Supporting Evidence) ==========
        
        # Path anomalies
        if feature_vector.get('working_directory_anomaly', 0) > 0:
            score += 5.0
        if feature_vector.get('executable_path_mismatch', 0) > 0:
            score += 6.0
        
        # User interactivity
        if feature_vector.get('user_interactivity_anomaly', 0) > 0:
            score += 5.0
        if feature_vector.get('unexpected_gui_access', 0) > 0:
            score += 4.0
        if feature_vector.get('unexpected_clipboard_access', 0) > 0:
            score += 6.0
        
        # Temporal correlation
        if feature_vector.get('temporal_correlation_spikes', 0) > 5:
            score += 6.0
        
        # Baseline deviation
        baseline_dev = feature_vector.get('baseline_deviation_score', 0)
        if baseline_dev > 5:
            score += 8.0
        elif baseline_dev > 2:
            score += 4.0
        
        # CPU/RAM spikes (supporting evidence)
        cpu_spike = feature_vector.get('cpu_spike_deviation', 0)
        if cpu_spike > 50:
            score += 6.0
        elif cpu_spike > 30:
            score += 4.0
        
        if feature_vector.get('sudden_ram_spikes', 0) > 0:
            score += 4.0
        
        # I/O volume
        total_bytes = feature_vector.get('total_bytes_written', 0)
        if total_bytes > 100000000:  # > 100MB
            score += 8.0
        elif total_bytes > 10000000:  # > 10MB
            score += 5.0
        
        # Clamp to 0-100
        final_score = max(0.0, min(100.0, score))
        
        if final_score > 0:
            logger.debug(f"Static scorer: Final score = {final_score:.2f} (from {score:.2f} before clamping)")
        
        return final_score
    
    def get_tier(self, score: float) -> str:
        """
        Get risk tier for a score.
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            Tier name: 'low', 'medium', 'high', or 'critical'
        """
        if score < self.tier_low_max + 1.0:
            return 'low'
        elif score < self.tier_medium_max + 1.0:
            return 'medium'
        elif score < self.tier_high_max + 1.0:
            return 'high'
        else:
            return 'critical'
    
    def should_promote_to_stage4(self, score: float) -> bool:
        """
        Determine if score should be promoted to Stage 4.
        
        Only Medium (60-79) and Critical (95-100) tiers go to Stage 4.
        High (80-94) tier gets immediate response without Stage 4.
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            True if score should go to Stage 4
        """
        tier = self.get_tier(score)
        # Only Medium and Critical tiers go to Stage 4
        return tier in ['medium', 'critical']
    
    def should_promote(self, score: float) -> bool:
        """
        Legacy method: Determine if score should be promoted to Stage 4.
        Uses old single threshold logic.
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            True if score >= threshold
        """
        return score >= self.threshold
    
    def get_threshold(self) -> float:
        """Get current promotion threshold (legacy)"""
        return self.threshold
    
    def set_threshold(self, threshold: float) -> None:
        """Set promotion threshold (legacy)"""
        self.threshold = max(0.0, min(100.0, threshold))
        logger.info(f"ML scorer threshold set to {self.threshold}")

###