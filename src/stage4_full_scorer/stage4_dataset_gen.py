"""
Stage 4 Training Dataset Generator - Fixed Version

Generates Stage 4 training dataset from Stage 3 parquet.
"""

import argparse
import json
import logging
import sqlite3
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Any

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("stage4_dataset_generator")


@dataclass
class Stage4Sample:
    """One training sample for Stage 4 model"""
    sample_id: str
    pid: int
    image: str
    host: str
    parent_pid: Optional[int] = None
    start_epoch: float = 0.0
    end_epoch: float = 0.0
    label: int = -1
    
    stage3_score_max: float = 0.0
    stage3_score_mean: float = 0.0
    stage3_score_std: float = 0.0
    stage3_tier_low_count: int = 0
    stage3_tier_medium_count: int = 0
    stage3_tier_high_count: int = 0
    stage3_tier_critical_count: int = 0
    yara_weighted_confidence_max: float = 0.0
    behavioral_signal_count_total: int = 0
    events_promoted_from_stage3: int = 0
    
    parent_chain_depth: int = 0
    sibling_count: int = 0
    child_count: int = 0
    tree_depth: int = 0
    
    process_age_sec: float = 0.0
    event_rate_per_sec: float = 0.0
    first_stage3_alert_sec: float = -1.0
    alert_onset_ratio: float = 1.0
    stage3_promotion_rate: float = 0.0
    
    is_signed: bool = False
    is_microsoft_signed: bool = False
    path_anomaly: bool = False
    
    stage3_elevation_anomaly: float = 0.0
    yara_context: str = ""
    yara_match_count: int = 0
    features: Dict[str, float] = field(default_factory=dict, repr=False)


class Stage4DatasetGenerator:
    """Build Stage 4 training dataset from Stage 3 parquet + labels"""
    
    def __init__(self, stage3_dir: str, label_db: Optional[str] = None, min_events: int = 2):
        self.stage3_dir = Path(stage3_dir)
        self.label_db = Path(label_db) if label_db else None
        self.min_events = int(min_events)
        self.labels: Dict[str, int] = {}
        self.stage3_events: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        
        if self.label_db and self.label_db.exists():
            self._load_labels()
    
    def _load_labels(self) -> None:
        """Load labels from SQLite database"""
        try:
            conn = sqlite3.connect(str(self.label_db))
            cur = conn.cursor()
            cur.execute("SELECT event_uuid, label FROM stage3_labels WHERE label IN (0, 1)")
            for uuid, label in cur.fetchall():
                self.labels[str(uuid)] = int(label)
            conn.close()
            logger.info(f"Loaded {len(self.labels)} labels from {self.label_db}")
        except Exception as e:
            logger.warning(f"Failed to load labels: {e}")
    
    def load_stage3_parquet(self) -> None:
        """Load all Stage 3 parquet files"""
        parquet_files = []
        
        # Try raw subdirectory first
        raw_dir = self.stage3_dir / "raw"
        if raw_dir.exists():
            parquet_files = list(raw_dir.rglob("*.parquet"))
            logger.info(f"Found {len(parquet_files)} parquet files in {raw_dir}")
        else:
            # Try direct files
            direct_files = list(self.stage3_dir.glob("*.parquet"))
            if direct_files:
                parquet_files = direct_files
                logger.info(f"Found {len(parquet_files)} parquet files directly in {self.stage3_dir}")
            else:
                logger.error(f"Stage 3 parquet files not found")
                return
        
        for pq_file in parquet_files:
            try:
                table = pq.read_table(pq_file)
                df = table.to_pydict()
                
                n_rows = len(next(iter(df.values()))) if df else 0
                for i in range(n_rows):
                    event = {k: v[i] if isinstance(v, list) else v for k, v in df.items()}
                    pid = int(event.get("pid", -1) or -1)
                    if pid > 0:
                        self.stage3_events[pid].append(event)
            except Exception as e:
                logger.warning(f"Error reading {pq_file}: {e}")
        
        logger.info(f"Loaded {sum(len(v) for v in self.stage3_events.values())} events for {len(self.stage3_events)} PIDs")
    
    def _get_label_for_events(self, events: List[Dict[str, Any]]) -> int:
        """Determine label for a PID"""
        label_votes = []
        ransomware_votes = []

        for event in events:
            label_val = event.get("label")
            if label_val in (0, 1):
                label_votes.append(int(label_val))

            ransomware_val = event.get("is_ransomware")
            if ransomware_val in (0, 1):
                ransomware_votes.append(int(ransomware_val))

        if label_votes:
            counts = Counter(label_votes)
            return 1 if counts[1] >= counts[0] else 0

        if ransomware_votes:
            counts = Counter(ransomware_votes)
            return 1 if counts[1] >= counts[0] else 0

        for event in events:
            uuid = str(event.get("event_uuid", "") or "")
            if uuid in self.labels:
                return self.labels[uuid]
        
        max_score = max((float(e.get("stage3_score", 0)  or 0) for e in events), default=0.0)
        yara_max = max((float(e.get("yara_weighted_confidence", 0) or 0) for e in events), default=0.0)
        
        if max_score >= 60.0:
            return 1
        elif max_score < 20.0 and yara_max < 0.1:
            return 0
        else:
            return -1
    
    def generate_samples(self) -> List[Stage4Sample]:
        """Generate Stage 4 samples"""
        samples = []
        
        for pid, events in self.stage3_events.items():
            if len(events) < self.min_events:
                continue
            
            try:
                sample = self._build_sample(pid, events)
                if sample:
                    samples.append(sample)
            except Exception as e:
                logger.warning(f"Error building sample for PID {pid}: {e}")
        
        logger.info(f"Generated {len(samples)} Stage 4 samples")
        return samples
    
    def _build_sample(self, pid: int, events: List[Dict[str, Any]]) -> Optional[Stage4Sample]:
        """Build a Stage 4 sample"""
        if not events:
            return None

        excluded_fields = {
            "process_guid", "window_index", "timestamp", "window_start_ts",
            "host_id", "pid", "attack_scenario_id", "label_source", "split",
            "attack_stage", "mitre_techniques", "evasion_type", "label_name",
            "label", "is_ransomware",
        }
        
        first_event = events[0]
        image = str(first_event.get("attack_stage", "") or "")
        host = str(first_event.get("host_id", "") or "")
        
        ts = first_event.get("timestamp")
        if ts is None:
            ts = 0
        sample_id = f"{host}_{pid}_{int(ts)}"
        
        timestamps = []
        for e in events:
            ts_val = e.get("timestamp")
            if ts_val is not None:
                try:
                    timestamps.append(float(ts_val))
                except (ValueError, TypeError):
                    pass
        
        start_epoch = min(timestamps) if timestamps else 0.0
        end_epoch = max(timestamps) if timestamps else 0.0
        
        sample = Stage4Sample(
            sample_id=sample_id,
            pid=pid,
            image=image,
            host=host,
            parent_pid=int(first_event.get("parent_pid", -1) or -1),
            start_epoch=start_epoch,
            end_epoch=end_epoch,
        )
        
        sample.label = self._get_label_for_events(events)
        sample.parent_chain_depth = int(first_event.get("spawn_depth", 0) or 0)
        sample.sibling_count = int(first_event.get("sibling_count", 0) or 0)
        sample.is_signed = float(first_event.get("signature_trust_level", 0) or 0) > 0.5
        sample.is_microsoft_signed = bool(first_event.get("is_microsoft_signed", 0) or 0)
        sample.path_anomaly = bool(
            first_event.get("working_directory_anomaly", 0) or first_event.get("executable_path_mismatch", 0)
        )

        numeric_values: Dict[str, List[float]] = defaultdict(list)
        for e in events:
            for key, value in e.items():
                if key in excluded_fields or value is None:
                    continue
                if isinstance(value, bool):
                    numeric_values[key].append(float(int(value)))
                elif isinstance(value, (int, float, np.integer, np.floating)):
                    numeric_values[key].append(float(value))

        feature_values: Dict[str, float] = {}
        for key, values in numeric_values.items():
            if not values:
                continue
            arr = np.asarray(values, dtype=np.float64)
            feature_values[f"{key}_mean"] = float(arr.mean())
            feature_values[f"{key}_max"] = float(arr.max())
            feature_values[f"{key}_std"] = float(arr.std()) if arr.size > 1 else 0.0

        sample.features = feature_values

        sample.stage3_score_max = float(feature_values.get("baseline_deviation_score_max", 0.0))
        sample.stage3_score_mean = float(feature_values.get("baseline_deviation_score_mean", 0.0))
        sample.stage3_score_std = float(feature_values.get("baseline_deviation_score_std", 0.0))
        sample.stage3_tier_low_count = int(first_event.get("files_created", 0) or 0)
        sample.stage3_tier_medium_count = int(first_event.get("files_modified", 0) or 0)
        sample.stage3_tier_high_count = int(first_event.get("files_deleted", 0) or 0)
        sample.stage3_tier_critical_count = int(first_event.get("injection_edge_flag", 0) or 0)
        sample.yara_weighted_confidence_max = float(feature_values.get("yara_weighted_confidence_max", 0.0))
        sample.behavioral_signal_count_total = int(sum(
            float(first_event.get(name, 0) or 0)
            for name in [
                "files_created", "files_modified", "files_deleted", "network_connections",
                "dns_lookup_count", "suspicious_api_call_frequency", "excessive_crypt_apis",
                "excessive_virtualalloc", "excessive_writeprocessmemory", "excessive_createremotethread",
            ]
        ))
        sample.events_promoted_from_stage3 = len(events)
        
        # Temporal
        if end_epoch > start_epoch:
            sample.process_age_sec = end_epoch - start_epoch
            sample.event_rate_per_sec = sample.events_promoted_from_stage3 / sample.process_age_sec
        
        # YARA
        yara_contexts = [str(e.get("yara_context", "") or "") for e in events if e.get("yara_context")]
        if yara_contexts:
            sample.yara_context = yara_contexts[0]
            sample.yara_match_count = len(yara_contexts)
        
        # Risk
        if sample.stage3_tier_critical_count > 0 and len(events) > 0:
            sample.stage3_elevation_anomaly = sample.stage3_tier_critical_count / len(events)
        
        return sample
    
    def save_to_parquet(self, samples: List[Stage4Sample], output_dir: str) -> None:
        """Save samples to parquet"""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        
        data = []
        for sample in samples:
            row = asdict(sample)
            feature_values = row.pop("features", {}) or {}
            row.update(feature_values)
            data.append(row)

        table = pa.Table.from_pylist(data)
        output_file = out_path / "stage4_train.parquet"
        pq.write_table(table, output_file, compression="zstd")
        logger.info(f"Saved {len(samples)} samples to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Generate Stage 4 training dataset")
    parser.add_argument("--stage3-dir", type=str, default="data/stage3", help="Path to Stage 3 dataset")
    parser.add_argument("--output-dir", type=str, default="data/stage4", help="Output directory")
    parser.add_argument("--label-db", type=str, default="src/dashboard/dashboard.db", help="SQLite DB with labels")
    parser.add_argument("--min-events", type=int, default=2, help="Minimum events per PID")
    
    args = parser.parse_args()
    
    logger.info("=" * 80)
    logger.info("Stage 4 Dataset Generator")
    logger.info("=" * 80)
    logger.info(f"Stage 3 dir: {args.stage3_dir}")
    logger.info(f"Output dir: {args.output_dir}")
    logger.info(f"Label DB: {args.label_db}")
    
    gen = Stage4DatasetGenerator(
        stage3_dir=args.stage3_dir,
        label_db=args.label_db,
        min_events=args.min_events,
    )
    
    gen.load_stage3_parquet()
    samples = gen.generate_samples()
    
    if samples:
        gen.save_to_parquet(samples, args.output_dir)
        logger.info(f"\n✓ Generated {len(samples)} Stage 4 training samples\n")
    else:
        logger.warning("No samples generated\n")


if __name__ == "__main__":
    main()
