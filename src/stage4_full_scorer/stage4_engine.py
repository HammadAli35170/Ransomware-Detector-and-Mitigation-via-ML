"""
Stage 4 Engine: Full Scorer

Orchestrates all Stage 4 analysis components:
- Graph Analytics
- Temporal Behavior Model
- ML Full Classifier
- Rule Engine
- Decision Engine
"""

import logging
import os
import threading
import time
from typing import Dict, Any, Optional, Callable
from collections import OrderedDict
from pathlib import Path

from .graph_analyzer import GraphAnalyzer
from .temporal_model import TemporalModel
from .ml_classifier import MLStage4Classifier
from .rule_engine import RuleEngine
from .decision_engine import DecisionEngine, DecisionResult

logger = logging.getLogger("stage4_engine")


class Stage4Engine:
    """
    Stage 4 Full Scorer Engine.
    
    Receives events from Stage 3 and performs comprehensive analysis
    using graph analytics, temporal modeling, ML classification, and rules.
    """
    
    def __init__(
        self,
        tabnet_model_path: Optional[str] = None,
        ensemble_model_path: Optional[str] = None,
        stage5_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        use_ensemble: bool = True,
        enable_verdict_cache: bool = True,
        verdict_cache_ttl_sec: int = 300,
        verdict_cache_max_size: int = 5000,
    ):
        """
        Initialize Stage 4 Engine.
        
        Args:
            tabnet_model_path: Path to TabNet model file
            ensemble_model_path: Path to ensemble model file
            stage5_callback: Callback for events promoted to Stage 5
            use_ensemble: Whether to use ensemble ML models
            
        Note: YARA scanning has been moved to Stage 3 for faster detection.
        """
        # Initialize components
        self.graph_analyzer = GraphAnalyzer()
        self.temporal_model = TemporalModel()
        # ML Classifier is optional; load if model artifacts are available.
        self.ml_classifier = None
        try:
            explicit_model_candidates = []
            for candidate in (tabnet_model_path, ensemble_model_path):
                if not candidate:
                    continue
                candidate_path = Path(candidate)
                if candidate_path.is_dir():
                    explicit_model_candidates.extend([
                        candidate_path / f"{candidate_path.name}.txt",
                        candidate_path / "stage4_v2_phasea.txt",
                        candidate_path / "stage4_v1.txt",
                    ])
                else:
                    explicit_model_candidates.append(candidate_path)

            model_candidates = [
                Path("models/stage4_v2_phasea/stage4_v2_phasea.txt"),
                Path("models/stage4_v1/stage4_v1.txt"),
                Path("models/stage4_v1.txt"),
            ]
            model_candidates = explicit_model_candidates + model_candidates
            model_path = next((p for p in model_candidates if p.exists()), None)
            if model_path is not None:
                config_path = model_path.with_suffix(".config.json")
                importance_path = model_path.with_suffix(".importance.json")
                self.ml_classifier = MLStage4Classifier(
                    model_path=str(model_path),
                    config_path=str(config_path),
                    importance_path=str(importance_path)
                )
                logger.info(f"Stage 4 ML classifier loaded from {model_path}")
            else:
                logger.info("Stage 4 ML model artifacts not found; running without ML classifier")
        except Exception as e:
            logger.debug(f"Stage 4 ML classifier not available: {e}")
        
        self.rule_engine = RuleEngine()  # No YARA - moved to Stage 3
        self.decision_engine = DecisionEngine()
        
        self.stage5_callback = stage5_callback

        # Verdict cache scaffolding: reduces duplicate analysis for repeated events per PID.
        self.enable_verdict_cache = bool(enable_verdict_cache)
        self.verdict_cache_ttl_sec = max(1, int(verdict_cache_ttl_sec))
        self.verdict_cache_max_size = max(10, int(verdict_cache_max_size))
        self._verdict_cache: "OrderedDict[int, tuple[DecisionResult, float]]" = OrderedDict()
        self.cache_hits = 0
        self.cache_misses = 0
        
        self.total_processed = 0
        self.total_promoted_to_stage5 = 0
        self.total_classified_malicious = 0
        self.total_classified_benign = 0
        self.total_classified_unknown = 0
        
        self._lock = threading.RLock()
        
        logger.info("Stage4Engine initialized")
    
    def process_event(self, event: Dict[str, Any]) -> DecisionResult:
        """
        Process an event from Stage 3 and perform full analysis.
        
        Args:
            event: Event dictionary from Stage 3 (must have ProcessID and Stage 3 features)
            
        Returns:
            DecisionResult with final classification
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
                logger.warning("Stage4: Event missing PID")
                return self._create_unknown_result("missing_pid")

            cached_decision = self._get_cached_decision(pid)
            if cached_decision is not None:
                event['__stage4'] = True
                event['__stage4_verdict'] = cached_decision.verdict.value
                event['__stage4_score'] = cached_decision.score
                event['__stage4_confidence'] = cached_decision.confidence
                event['__stage4_reasons'] = list(cached_decision.reasoning or [])
                event['__stage4_timestamp'] = time.time()
                return cached_decision
            
            with self._lock:
                self.total_processed += 1
            
            # Get Stage 3 features
            stage3_features = event.get("__stage3_features", {})
            stage3_score = event.get("__stage3_score", 0.0)
            
            # Update graph analyzer
            self.graph_analyzer.add_event(event)
            
            # Update temporal model
            self.temporal_model.add_event(event)
            
            # Analyze with graph analyzer
            image_path = event.get("Image") or event.get("image") or ""
            graph_metrics_dict = self._graph_metrics_to_dict(
                self.graph_analyzer.analyze_process(pid)
            )
            
            # Analyze with temporal model
            temporal_metrics_dict = self._temporal_metrics_to_dict(
                self.temporal_model.analyze_process(pid, image_path)
            )
            
            # ML classification
            if self.ml_classifier is not None:
                ml_features = self._build_stage4_ml_features(
                    stage3_features=stage3_features,
                    graph_features=graph_metrics_dict,
                    temporal_features=temporal_metrics_dict,
                )
                ml_result = self.ml_classifier.classify(ml_features)
            else:
                from .ml_classifier import ClassificationResult
                ml_result = ClassificationResult(
                    prediction="unknown",
                    confidence=0.0,
                    probability=0.5,
                    model_used="disabled",
                    explainability={},
                )
            
            # Rule evaluation
            combined_features = {}
            combined_features.update(stage3_features)
            combined_features.update(graph_metrics_dict)
            combined_features.update(temporal_metrics_dict)
            combined_features['__reasons'] = event.get("__reasons", [])
            
            rule_matches = self.rule_engine.evaluate(
                event=event,
                features=combined_features,
                file_path=image_path if image_path and os.path.exists(image_path) else None
            )
            
            # Make final decision
            decision = self.decision_engine.make_decision(
                ml_result=ml_result,
                graph_metrics=graph_metrics_dict,
                temporal_metrics=temporal_metrics_dict,
                rule_matches=rule_matches,
                stage3_score=stage3_score
            )

            # Attach Stage 4 analysis data for downstream consumers and dashboard.
            event['__stage4'] = True
            event['__stage4_verdict'] = decision.verdict.value
            event['__stage4_score'] = decision.score
            event['__stage4_confidence'] = decision.confidence
            event['__stage4_reasons'] = list(decision.reasoning or [])
            event['__stage4_graph'] = graph_metrics_dict
            event['__stage4_temporal'] = temporal_metrics_dict
            event['__stage4_ml'] = {
                'prediction': ml_result.prediction,
                'confidence': ml_result.confidence,
                'probability': ml_result.probability,
                'model_used': ml_result.model_used,
                'explainability': ml_result.explainability or {},
            }
            event['__stage4_timestamp'] = time.time()
            
            # Update statistics
            with self._lock:
                if decision.verdict.value == "malicious":
                    self.total_classified_malicious += 1
                elif decision.verdict.value == "benign":
                    self.total_classified_benign += 1
                else:
                    self.total_classified_unknown += 1
                
                # Promote to Stage 5 if malicious or suspicious
                if decision.verdict.value in ["malicious", "suspicious"]:
                    self.total_promoted_to_stage5 += 1
                    event['__stage4_decision'] = decision
                    
                    # Forward to Stage 5
                    if self.stage5_callback:
                        try:
                            self.stage5_callback(event)
                        except Exception:
                            logger.exception(f"Stage5 callback failed for PID {pid}")
                    
                    logger.warning(
                        f"Stage4 → Stage5: PID={pid} Verdict={decision.verdict.value} "
                        f"Score={decision.score:.2f} Confidence={decision.confidence:.2f}"
                    )

            self._cache_decision(pid, decision)
            
            return decision
            
        except Exception:
            logger.exception(f"Error processing event in Stage4: {event.get('EventID', 'unknown')}")
            return self._create_unknown_result("processing_error")
    
    def _graph_metrics_to_dict(self, metrics) -> Dict[str, float]:
        """Convert GraphMetrics to dictionary"""
        return {
            'process_tree_depth': float(metrics.process_tree_depth),
            'process_tree_width': float(metrics.process_tree_width),
            'total_descendants': float(metrics.total_descendants),
            'network_degree': float(metrics.network_degree),
            'file_access_degree': float(metrics.file_access_degree),
            'centrality_score': float(metrics.centrality_score),
            'clustering_coefficient': float(metrics.clustering_coefficient),
            'relationship_anomaly_score': float(metrics.relationship_anomaly_score),
            'isolated_process': 1.0 if metrics.isolated_process else 0.0,
            'unusual_parent': 1.0 if metrics.unusual_parent else 0.0,
            'unusual_spawning_pattern': 1.0 if metrics.unusual_spawning_pattern else 0.0
        }
    
    def _temporal_metrics_to_dict(self, metrics) -> Dict[str, float]:
        """Convert TemporalMetrics to dictionary"""
        return {
            'baseline_deviation_score': float(metrics.baseline_deviation_score),
            'entropy_trend': float(metrics.entropy_trend),
            'io_trend': float(metrics.io_trend),
            'burst_detection_score': float(metrics.burst_detection_score),
            'time_series_anomaly': float(metrics.time_series_anomaly),
            'long_window_entropy_avg': float(metrics.long_window_entropy_avg),
            'long_window_entropy_std': float(metrics.long_window_entropy_std),
            'io_acceleration': float(metrics.io_acceleration),
            'pattern_match_score': float(metrics.pattern_match_score)
        }

    def _build_stage4_ml_features(
        self,
        stage3_features: Dict[str, Any],
        graph_features: Dict[str, float],
        temporal_features: Dict[str, float],
    ) -> Dict[str, float]:
        """
        Build a feature dictionary compatible with the trained Stage 4 model.

        The current model was trained on PID-level aggregate features with
        suffixes (_mean/_max/_std). At runtime we have mostly event-level
        values, so we project each numeric value into mean/max and set std=0.
        """
        features: Dict[str, float] = {}

        def add_numeric_projection(name: str, value: Any) -> None:
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return
            features[f"{name}_mean"] = numeric
            features[f"{name}_max"] = numeric
            features[f"{name}_std"] = 0.0

        for name, value in (stage3_features or {}).items():
            add_numeric_projection(str(name), value)

        for name, value in (graph_features or {}).items():
            add_numeric_projection(str(name), value)

        for name, value in (temporal_features or {}).items():
            add_numeric_projection(str(name), value)

        # Preserve raw graph/temporal values for any non-aggregated model features.
        for name, value in (graph_features or {}).items():
            try:
                features[str(name)] = float(value)
            except (TypeError, ValueError):
                continue
        for name, value in (temporal_features or {}).items():
            try:
                features[str(name)] = float(value)
            except (TypeError, ValueError):
                continue

        return features
    
    def _create_unknown_result(self, reason: str) -> DecisionResult:
        """Create an unknown result for error cases"""
        from .decision_engine import FinalVerdict
        return DecisionResult(
            verdict=FinalVerdict.UNKNOWN,
            confidence=0.0,
            score=0.0,
            reasoning=[f"Error: {reason}"]
        )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get Stage 4 metrics"""
        with self._lock:
            total_cache = self.cache_hits + self.cache_misses
            cache_hit_rate = (self.cache_hits / total_cache * 100.0) if total_cache > 0 else 0.0
            return {
                'total_processed': self.total_processed,
                'total_promoted_to_stage5': self.total_promoted_to_stage5,
                'total_malicious': self.total_classified_malicious,
                'total_benign': self.total_classified_benign,
                'total_unknown': self.total_classified_unknown,
                'verdict_cache_enabled': self.enable_verdict_cache,
                'verdict_cache_entries': len(self._verdict_cache),
                'verdict_cache_ttl_sec': self.verdict_cache_ttl_sec,
                'verdict_cache_max_size': self.verdict_cache_max_size,
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'cache_hit_rate': cache_hit_rate,
                'promotion_rate': (
                    self.total_promoted_to_stage5 / max(1, self.total_processed) * 100
                ),
                'malicious_rate': (
                    self.total_classified_malicious / max(1, self.total_processed) * 100
                )
            }
    
    def cleanup(self) -> None:
        """Cleanup old data"""
        self.graph_analyzer.cleanup_old_processes()
        self.temporal_model.cleanup_old_data()
        self._cleanup_verdict_cache()

    def _get_cached_decision(self, pid: int) -> Optional[DecisionResult]:
        """Return cached decision for PID if present and fresh."""
        if not self.enable_verdict_cache:
            return None
        now = time.time()
        with self._lock:
            cached = self._verdict_cache.get(pid)
            if not cached:
                self.cache_misses += 1
                return None
            decision, ts = cached
            if (now - ts) > self.verdict_cache_ttl_sec:
                del self._verdict_cache[pid]
                self.cache_misses += 1
                return None
            self.cache_hits += 1
            self._verdict_cache.move_to_end(pid)
            return decision

    def _cache_decision(self, pid: int, decision: DecisionResult) -> None:
        """Store decision in bounded LRU cache."""
        if not self.enable_verdict_cache:
            return
        with self._lock:
            self._verdict_cache[pid] = (decision, time.time())
            self._verdict_cache.move_to_end(pid)
            while len(self._verdict_cache) > self.verdict_cache_max_size:
                self._verdict_cache.popitem(last=False)

    def _cleanup_verdict_cache(self) -> None:
        """Remove expired verdict cache entries."""
        if not self.enable_verdict_cache:
            return
        now = time.time()
        with self._lock:
            expired = [pid for pid, (_, ts) in self._verdict_cache.items() if (now - ts) > self.verdict_cache_ttl_sec]
            for pid in expired:
                self._verdict_cache.pop(pid, None)


# Global engine instance
_ENGINE: Optional[Stage4Engine] = None


def get_stage4_engine() -> Optional[Stage4Engine]:
    """Get global Stage 4 engine instance"""
    return _ENGINE


def initialize_stage4(
    model_path: Optional[str] = None,
    tabnet_model_path: Optional[str] = None,
    ensemble_model_path: Optional[str] = None,
    stage5_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    **kwargs
) -> Stage4Engine:
    """
    Initialize global Stage 4 engine.
    
    Args:
        tabnet_model_path: Path to TabNet model
        ensemble_model_path: Path to ensemble model
        stage5_callback: Callback for Stage 5 events
        **kwargs: Additional arguments
        
    Note: YARA scanning has been moved to Stage 3 for faster detection.
        
    Returns:
        Initialized Stage4Engine instance
    """
    global _ENGINE
    _ENGINE = Stage4Engine(
        tabnet_model_path=model_path or tabnet_model_path,
        ensemble_model_path=ensemble_model_path,
        stage5_callback=stage5_callback,
        **kwargs
    )
    logger.info("Global Stage4Engine initialized (YARA moved to Stage 3)")
    return _ENGINE

