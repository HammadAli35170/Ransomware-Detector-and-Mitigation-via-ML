"""
Wrapper module for `src.stage3_feature_extraction.materialize_dataset`.

Allows running:
  python -m stage3_feature_extraction.materialize_dataset --dataset-dir ... --out ...
"""

from __future__ import annotations

from src.stage3_feature_extraction.materialize_dataset import main  # type: ignore


if __name__ == "__main__":
    raise SystemExit(main())


