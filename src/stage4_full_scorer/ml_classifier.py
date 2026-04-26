"""
ML Classifier for Stage 4

LightGBM-based binary classifier for Stage 4 (malicious vs benign).
Provides confidence scores and basic explainability via feature importance.
"""

import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Any

import numpy as np

logger = logging.getLogger("stage4_ml_classifier")

# LightGBM
try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False
    logger.warning("LightGBM not available. Install with: pip install lightgbm")


@dataclass
class ClassificationResult:
    """Result from ML classifier"""
    prediction: str  # "malicious", "benign", "unknown"
    confidence: float  # 0.0 to 1.0
    probability: float  # Raw model output (0.0-1.0)
    model_used: str = "stage4_lgb"  # Which model made the prediction
    explainability: Optional[Dict[str, float]] = None  # Top feature importance


class MLStage4Classifier:
    """
    LightGBM-based classifier for Stage 4.
    
    Provides:
    - Binary classification (Malicious / Benign)
    - Confidence scores
    - Top contributing features
    """
    
    def __init__(
        self,
        model_path: str,
        config_path: str,
        importance_path: Optional[str] = None,
        malicious_threshold: float = 0.6,
        unknown_threshold: float = 0.4
    ):
        """
        Initialize Stage 4 ML Classifier.
        
        Args:
            model_path: Path to LightGBM model (.txt)
            config_path: Path to model config (.json)
            importance_path: Path to feature importance (.json)
            malicious_threshold: Confidence threshold >= this = malicious
            unknown_threshold: Confidence threshold below = unknown
        """
        self.model_path = Path(model_path)
        self.config_path = Path(config_path)
        self.importance_path = Path(importance_path) if importance_path else None
        
        self.malicious_threshold = malicious_threshold
        self.unknown_threshold = unknown_threshold
        
        self.model = None
        self.config = {}
        self.feature_importance = {}
        self.feature_names = []
        
        self._load_model()
    
    def _load_model(self) -> None:
        """Load LightGBM model and config"""
        if not LIGHTGBM_AVAILABLE:
            raise RuntimeError("LightGBM not available")
        
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        
        try:
            self.model = lgb.Booster(model_file=str(self.model_path))
            logger.info(f"Loaded Stage 4 LightGBM model from {self.model_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to load model: {e}")
        
        # Load config
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    self.config = json.load(f)
                self.feature_names = self.config.get("feature_names", [])
                logger.info(f"Loaded config with {len(self.feature_names)} features")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")
        
        # Load feature importance
        if self.importance_path and self.importance_path.exists():
            try:
                with open(self.importance_path) as f:
                    self.feature_importance = json.load(f)
                logger.info(f"Loaded feature importance with {len(self.feature_importance)} features")
            except Exception as e:
                logger.warning(f"Failed to load importance: {e}")
        
        logger.info("MLStage4Classifier initialized")
    
    def classify(
        self,
        features: Optional[Dict[str, float]] = None,
        stage3_features: Optional[Dict[str, Any]] = None,
        stage4_graph_features: Optional[Dict[str, Any]] = None,
        stage4_temporal_features: Optional[Dict[str, Any]] = None,
    ) -> ClassificationResult:
        """
        Classify a process using Stage 4 features.
        
        Args:
            features: Feature dict with all Stage 4 feature values
            
        Returns:
            ClassificationResult with prediction and confidence
        """
        try:
            merged_features: Dict[str, float] = {}
            if features:
                merged_features.update(features)

            for group in (stage3_features, stage4_graph_features, stage4_temporal_features):
                if not group:
                    continue
                for key, value in group.items():
                    try:
                        merged_features[str(key)] = float(value)
                    except (TypeError, ValueError):
                        continue

            # Convert features dict to ordered array
            feature_array = self._features_to_array(merged_features)
            
            # Get prediction from LightGBM
            probability = float(self.model.predict(np.array([feature_array]))[0])
            
            # Determine verdict based on probability and thresholds
            if probability >= self.malicious_threshold:
                prediction = "malicious"
                confidence = probability
            elif probability <= self.unknown_threshold:
                prediction = "benign"
                confidence = 1.0 - probability
            else:
                prediction = "unknown"
                confidence = 0.5 - abs(probability - 0.5)  # Uncertainty score
            
            # Get top contributing features
            explainability = self._get_top_features(probability)
            
            return ClassificationResult(
                prediction=prediction,
                confidence=min(1.0, max(0.0, confidence)),
                probability=probability,
                model_used="stage4_lgb",
                explainability=explainability
            )
                
        except Exception as e:
            logger.exception(f"Error in ML classification: {e}")
            return ClassificationResult(
                prediction="unknown",
                confidence=0.0,
                probability=0.5,
                model_used="fallback"
            )
    
    def _features_to_array(self, features: Dict[str, float]) -> np.ndarray:
        """Convert features dict to ordered numpy array"""
        if not self.feature_names:
            # Fallback: use dict values in order
            return np.array(list(features.values()), dtype=np.float32)
        
        # Extract features in the correct order
        arr = []
        for fname in self.feature_names:
            val = features.get(fname, 0.0)
            # Handle bool
            if isinstance(val, bool):
                val = float(val)
            if val is None:
                val = 0.0
            try:
                numeric = float(val)
            except (TypeError, ValueError):
                numeric = 0.0
            if not math.isfinite(numeric):
                numeric = 0.0
            arr.append(numeric)
        
        return np.array(arr, dtype=np.float32)
    
    def _get_top_features(self, probability: float, top_k: int = 5) -> Dict[str, float]:
        """Get top contributing features for explainability"""
        if not self.feature_importance:
            return {}
        
        # Sort by importance
        sorted_features = sorted(
            self.feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return dict(sorted_features[:top_k])

