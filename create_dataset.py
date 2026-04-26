#!/usr/bin/env python3
"""Create training dataset from labeled events."""

from pathlib import Path
from src.dataset_collection.collection_engine import DatasetCollectionEngine

# Create dataset from batch_1
session_path = Path("data/dataset_sessions/batch_1")
engine = DatasetCollectionEngine(session_id="batch_1", session_name="batch_1")

print("Creating dataset from labeled events...")
try:
    dataset_path = engine.create_dataset()
    print(f"\n✓ Dataset created successfully!")
    print(f"  Location: {dataset_path}")
    print(f"  Ready for model training")
    
    # Show what was created
    if dataset_path:
        dataset_file = Path(dataset_path)
        if dataset_file.exists():
            size_mb = dataset_file.stat().st_size / (1024 * 1024)
            print(f"  File size: {size_mb:.2f} MB")
    
except Exception as e:
    print(f"✗ Error creating dataset: {e}")
    import traceback
    traceback.print_exc()
