"""
Stage 3: Feature Extraction + Fast ML Scoring

This stage receives events promoted from Stage 2 and:
1. Extracts comprehensive features per suspicious PID
2. Runs YARA scan (on-disk PE + memory regions)
3. Scores using LightGBM model (0-100) with YARA boost
4. Implements tiered thresholds:
   - Low (0-59): Benign, dropped
   - Medium (60-79): Forward to Stage 4
   - High (80-94): Immediate response, skip Stage 4
   - Critical (95-100): Nuclear response + Stage 4 forensics
"""

from .stage3_engine import Stage3Engine, get_stage3_engine, initialize_stage3, RiskTier, Stage3Result
from .yara_scanner import YaraScanner
from .ml_scorer2 import MLScorer
from .feature_extractor import FeatureExtractor
from .genealogy_builder import ProcessGenealogy, GenealogyTree

__all__ = [
    'Stage3Engine', 
    'get_stage3_engine', 
    'initialize_stage3',
    'RiskTier',
    'Stage3Result',
    'YaraScanner',
    'MLScorer',
    'FeatureExtractor',
    'ProcessGenealogy',
    'GenealogyTree'
]

