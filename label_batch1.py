#!/usr/bin/env python3
"""Quick script to label collected events as benign or malicious."""

import json
from pathlib import Path
from src.dataset_collection.annotation_manager import AnnotationManager, ThreatLabel

try:
    import pyarrow.parquet as pq
except ImportError:
    print("Installing pyarrow...")
    import subprocess
    subprocess.check_call(["pip", "install", "pyarrow"])
    import pyarrow.parquet as pq

# Label all events in batch_1 as BENIGN
session_path = Path("data/dataset_sessions/batch_1")

# Initialize annotation manager
manager = AnnotationManager(str(session_path))

# Find parquet file
parquet_dir = session_path / "raw" / "date=2026-01-30"
parquet_files = list(parquet_dir.glob("*.parquet"))

if not parquet_files:
    print(f"No parquet files found in {parquet_dir}")
    exit(1)

# Read and label each event from parquet
count = 0
for parquet_file in parquet_files:
    print(f"Reading {parquet_file.name}...")
    table = pq.read_table(parquet_file)
    
    # Convert to list of dicts without pandas
    for batch in table.to_batches():
        for i in range(batch.num_rows):
            row_dict = {}
            for col_idx, col_name in enumerate(table.column_names):
                row_dict[col_name] = batch[col_idx][i].as_py()
            
            event_uuid = row_dict.get("event_uuid")
            if not event_uuid:
                continue
            
            # Label as BENIGN with high confidence
            manager.add_annotation(
                feature_id=event_uuid,
                threat_type=ThreatLabel.BENIGN,
                confidence=0.95,  # High confidence for known benign processes
                notes=f"Legitimate process: {row_dict.get('image', 'unknown')}",
                tags=["system_process", "legitimate_network"]
            )
            count += 1
            print(f"  ✓ {event_uuid[:8]}... → BENIGN")

print(f"\n✓ Labeled {count} events total")

# Show statistics
stats = manager.get_stats()
print(f"\nLabel Statistics:")
print(f"  Total annotated: {stats['total_annotated']}")
if 'threat_type_counts' in stats:
    print(f"  Benign: {stats['threat_type_counts'].get('benign', 0)}")
    print(f"  Malicious: {sum(count for key, count in stats['threat_type_counts'].items() if key != 'benign')}")
