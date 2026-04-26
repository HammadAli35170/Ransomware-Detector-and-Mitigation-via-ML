"""
Materialize labeled Stage-3 dataset (Parquet) by joining:
  - raw Parquet samples (label=-1) written by Stage3DatasetRecorder
  - labels in SQLite table stage3_labels (dashboard + label-file matches)

Usage (PowerShell):
  python -m stage3_feature_extraction.materialize_dataset --dataset-dir data/stage3_dataset --out labeled.parquet
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Dict

import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.compute as pc
import pyarrow.parquet as pq


def _load_labels(db_path: Path) -> pa.Table:
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        cur.execute("SELECT event_uuid, label FROM stage3_labels")
        rows = cur.fetchall()
    finally:
        conn.close()
    return pa.Table.from_pylist([{"event_uuid": r[0], "label": int(r[1])} for r in rows])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", required=True, help="Dataset root dir (contains raw/)")
    ap.add_argument("--db", default="src/dashboard/dashboard.db", help="SQLite DB path containing stage3_labels")
    ap.add_argument("--out", required=True, help="Output labeled Parquet file")
    args = ap.parse_args()

    dataset_dir = Path(args.dataset_dir)
    raw_dir = dataset_dir / "raw"
    if not raw_dir.exists():
        raise SystemExit(f"raw dataset dir not found: {raw_dir}")

    labels = _load_labels(Path(args.db))
    raw = ds.dataset(str(raw_dir), format="parquet")
    raw_table = raw.to_table()

    if labels.num_rows == 0:
        # no labels yet; just write raw as-is
        pq.write_table(raw_table, args.out, compression="zstd")
        return 0

    # Join on event_uuid and overwrite label where available
    # pyarrow expects join_type like "left outer" (not "left_outer")
    joined = raw_table.join(labels, keys="event_uuid", join_type="left outer", right_suffix="_l")
    # joined has columns: label (raw -1), label_l (maybe null)
    final_label = pc.if_else(pc.is_null(joined["label_l"]), joined["label"], joined["label_l"])
    joined = joined.set_column(joined.schema.get_field_index("label"), "label", final_label)
    joined = joined.drop_columns(["label_l"])

    pq.write_table(joined, args.out, compression="zstd")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


