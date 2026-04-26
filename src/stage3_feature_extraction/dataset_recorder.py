"""
Stage 3 Dataset Recorder (Parquet)

Training mode writes Stage-3 feature vectors to Parquet immediately with label=-1.
Labels are stored separately (SQLite via dashboard + optional label-file matcher) and can be
materialized later into a labeled Parquet dataset.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, List

import sqlite3

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception:  # pragma: no cover
    pa = None
    pq = None


DEFAULT_DB_PATH = Path("src/dashboard/dashboard.db")


@dataclass
class LabelRule:
    label: int  # 0 benign, 1 malicious
    image_contains: Optional[str] = None
    pid: Optional[int] = None
    start_epoch: Optional[float] = None
    end_epoch: Optional[float] = None
    note: Optional[str] = None


class LabelMatcher:
    """Simple rule matcher loaded from a JSON label file (lab workflow)."""

    def __init__(self, label_file: Optional[str]):
        self.rules: List[LabelRule] = []
        if not label_file:
            return
        p = Path(label_file)
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(data, list):
            return
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                label = int(item.get("label"))
            except Exception:
                continue
            if label not in (0, 1):
                continue
            rule = LabelRule(
                label=label,
                image_contains=item.get("image_contains"),
                pid=int(item["pid"]) if item.get("pid") is not None else None,
                start_epoch=float(item["start_epoch"]) if item.get("start_epoch") is not None else None,
                end_epoch=float(item["end_epoch"]) if item.get("end_epoch") is not None else None,
                note=item.get("note"),
            )
            self.rules.append(rule)

    def match(self, *, pid: Optional[int], image: Optional[str], ts_epoch: float) -> Optional[LabelRule]:
        img = (image or "").lower()
        for r in self.rules:
            if r.pid is not None and pid is not None and int(pid) != int(r.pid):
                continue
            if r.image_contains and r.image_contains.lower() not in img:
                continue
            if r.start_epoch is not None and ts_epoch < r.start_epoch:
                continue
            if r.end_epoch is not None and ts_epoch > r.end_epoch:
                continue
            return r
        return None


class Stage3DatasetRecorder:
    """
    Records Stage-3 samples to Parquet.

    - Raw samples are written immediately with label=-1.
    - Labels are persisted to SQLite table `stage3_labels` (from dashboard or label-file matches).
    """

    def __init__(
        self,
        dataset_dir: str,
        feature_names: List[str],
        db_path: Optional[str] = None,
        label_file: Optional[str] = None,
        flush_every: int = 200,
        compression: str = "zstd",
    ):
        self.dataset_dir = Path(dataset_dir)
        self.raw_dir = self.dataset_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        self.feature_names = list(feature_names)
        self.flush_every = int(flush_every)
        self.compression = compression

        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_label_db()
        self.label_matcher = LabelMatcher(label_file)

        self._lock = threading.Lock()
        self._buffer: List[Dict[str, Any]] = []
        self._seq = 0

        if pa is None or pq is None:
            raise RuntimeError("pyarrow is required for Parquet dataset recording. Install: pip install pyarrow")

    def _init_label_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS stage3_labels (
                    event_uuid TEXT PRIMARY KEY,
                    label INTEGER,
                    source TEXT,
                    ts TEXT,
                    note TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def upsert_label(self, event_uuid: str, label: int, source: str, note: str = "") -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO stage3_labels(event_uuid, label, source, ts, note)
                VALUES(?,?,?,?,?)
                ON CONFLICT(event_uuid) DO UPDATE SET
                    label=excluded.label,
                    source=excluded.source,
                    ts=excluded.ts,
                    note=excluded.note
                """,
                (event_uuid, int(label), str(source), time.strftime("%Y-%m-%dT%H:%M:%S"), str(note or "")),
            )
            conn.commit()
        finally:
            conn.close()

    def record(self, event: Dict[str, Any]) -> None:
        """
        Record a Stage-3 processed event into raw Parquet buffer.
        Expects Stage3Engine to have annotated:
          - __event_uuid
          - __stage3_features (dict)
          - __stage3_score, __stage3_tier
          - optional YARA telemetry fields
        & we always write label=-1 (option A).
        """
        ts_epoch = float(event.get("__stage3_timestamp") or time.time())
        event_uuid = str(event.get("__event_uuid") or "")
        if not event_uuid:
            return

        pid = event.get("ProcessID") or event.get("pid")
        try:
            pid_int = int(pid) if pid is not None else None
        except Exception:
            pid_int = None

        image = event.get("Image") or event.get("image") or ""
        cmd = event.get("CommandLine") or event.get("command_line") or event.get("Message") or ""

        features = event.get("__stage3_features") or {}
        if not isinstance(features, dict):
            features = {}

        row: Dict[str, Any] = {
            "event_uuid": event_uuid,
            "ts_epoch": ts_epoch,
            "host": os.environ.get("COMPUTERNAME", ""),
            "pid": pid_int if pid_int is not None else -1,
            "image": str(image),
            "command_line": str(cmd)[:4096],
            "stage2_promoted": bool(event.get("__stage2") or False),
            "stage2_score": float(event.get("__score") or 0.0),
            "stage3_score": float(event.get("__stage3_score") or 0.0),
            "stage3_tier": str(event.get("__stage3_tier") or ""),
            # YARA telemetry
            "yara_context": str(event.get("__stage3_yara_context") or ""),
            "yara_context_weight": float(event.get("__stage3_yara_context_weight") or 0.0),
            "yara_weighted_confidence": float(event.get("__stage3_yara_weighted_confidence") or 0.0),
            "yara_boost": float(event.get("__stage3_yara_boost") or 0.0),
            "yara_escalation_allowed": bool(event.get("__stage3_yara_escalation_allowed", True)),
            "behavioral_signal_count": int(event.get("__stage3_behavioral_signal_count") or 0),
            "yara_downweight_reason": str(event.get("__stage3_yara_downweight_reason") or ""),
            # Label (Option A)
            "label": -1,
        }

        # Flatten features
        for fn in self.feature_names:
            try:
                row[fn] = float(features.get(fn, 0.0))
            except Exception:
                row[fn] = 0.0

        # Optional: auto-attach label into SQLite when label-file rules match
        rule = self.label_matcher.match(pid=pid_int, image=str(image), ts_epoch=ts_epoch)
        if rule is not None:
            self.upsert_label(event_uuid, rule.label, source="label_file", note=rule.note or "")

        with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= self.flush_every:
                self._flush_locked()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._buffer:
            return
        self._seq += 1
        batch = self._buffer
        self._buffer = []

        # Partition by date for manageability
        day = time.strftime("%Y-%m-%d", time.localtime(batch[-1].get("ts_epoch", time.time())))
        out_dir = self.raw_dir / f"date={day}"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"part-{int(time.time())}-{self._seq:05d}.parquet"

        table = pa.Table.from_pylist(batch)
        pq.write_table(table, out_path, compression=self.compression)


