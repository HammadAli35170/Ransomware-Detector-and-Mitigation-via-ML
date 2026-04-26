"""
Compatibility package.

The actual implementation lives under `src/stage3_feature_extraction/`, but many users naturally try:

  python -m stage3_feature_extraction.materialize_dataset ...

This wrapper keeps that command working without requiring PYTHONPATH tweaks.
"""


