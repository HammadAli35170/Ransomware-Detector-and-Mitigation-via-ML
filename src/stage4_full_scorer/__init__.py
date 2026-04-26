"""
Stage 4: Full Scorer

Comprehensive analysis combining:
- Graph Analytics (process tree, network, file access)
- Temporal Behavior Model (long-window metrics, baseline learning)
- ML Full Classifier (TabNet/Ensemble with confidence scores)
- Rule Engine (custom behavioral rules)
- Decision Engine (multi-factor scoring, final verdict)

Note: YARA scanning has been moved to Stage 3 for faster detection.

Future enhancements:
- Threat Intelligence integration (hooks ready)
- Sandbox integration (hooks ready)
"""

from .stage4_engine import Stage4Engine, get_stage4_engine, initialize_stage4

__all__ = ['Stage4Engine', 'get_stage4_engine', 'initialize_stage4']

