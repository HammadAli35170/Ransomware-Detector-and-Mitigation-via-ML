#!/usr/bin/env python3
"""
Training Mode Launcher for RDNXSYS EDR

Collects Stage 3 dataset for ML training:
- Records all Stage 2 promoted events (full features)
- Samples background events (non-promoted) at specified rate
- Writes Parquet files with label=-1 (raw, unlabeled)
- Labels can be added via dashboard or label file

Usage:
    python src/train_launcher.py
    python src/train_launcher.py --background-sample-rate 0.1
    python src/train_launcher.py --dataset-dir data/my_dataset --label-file labels.json
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from .unified_launcher import UnifiedEDRLauncher

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("TRAIN_LAUNCHER")


def main(
    dataset_dir: str = "data/stage3_dataset",
    label_file: Optional[str] = None,
    background_sample_rate: float = 0.01,
    host: str = "127.0.0.1",
    port: int = 5050,
):
    """
    Start training mode launcher.
    
    Args:
        dataset_dir: Directory to write Parquet dataset files
        label_file: Optional JSON label file for lab runs
        background_sample_rate: Sample rate for non-promoted events (0.0-1.0)
        host: TCP listener host
        port: TCP listener port
    """
    log.info("=" * 80)
    log.info("RDNXSYS EDR - TRAINING MODE")
    log.info("=" * 80)
    log.info(f"Dataset directory: {dataset_dir}")
    log.info(f"Background sample rate: {background_sample_rate * 100:.1f}%")
    if label_file:
        log.info(f"Label file: {label_file}")
    log.info("=" * 80)
    log.info("")
    log.info("Collecting dataset:")
    log.info("  ✓ All Stage 2 promoted events (full features)")
    log.info(f"  ✓ {background_sample_rate * 100:.1f}% of background events (sampled)")
    log.info("  ✓ Writing to Parquet with label=-1 (unlabeled)")
    log.info("")
    log.info("Label events via:")
    log.info("  • Dashboard: Click 'Benign' or 'Malicious' buttons")
    log.info("  • Label file: Edit JSON file during lab runs")
    log.info("")
    log.info("Materialize labeled dataset:")
    log.info("  python -m stage3_feature_extraction.materialize_dataset")
    log.info("    --dataset-dir data/stage3_dataset")
    log.info("    --out labeled.parquet")
    log.info("")
    
    # Create launcher with training mode enabled
    launcher = UnifiedEDRLauncher(
        host=host,
        port=port,
        training_mode=True,
        dataset_dir=dataset_dir,
        label_file=label_file,
        background_sample_rate=background_sample_rate,
    )
    
    # Setup event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    def _on_signal(sig, frame):
        log.info("Signal received, shutting down...")
        launcher.stop()
        # Cancel loop tasks
        for task in asyncio.all_tasks(loop):
            task.cancel()
    
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    
    try:
        log.info("Starting training launcher...")
        loop.run_until_complete(launcher.start())
    except KeyboardInterrupt:
        log.info("Stopped by KeyboardInterrupt")
    except Exception:
        log.exception("Training launcher crashed")
    finally:
        try:
            loop.close()
        except Exception:
            pass
        log.info("Training launcher stopped")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="RDNXSYS EDR Training Mode - Collect Stage 3 dataset for ML training",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic training mode (1% background sampling)
  python src/train_launcher.py
  
  # Higher background sampling rate (10%)
  python src/train_launcher.py --background-sample-rate 0.1
  
  # Custom dataset directory and label file
  python src/train_launcher.py --dataset-dir data/my_dataset --label-file labels.json
        """
    )
    
    parser.add_argument(
        "--dataset-dir",
        default="data/stage3_dataset",
        help="Directory to write Parquet dataset files (default: data/stage3_dataset)"
    )
    parser.add_argument(
        "--label-file",
        default=None,
        help="Optional JSON label file for lab runs (see DATASET_TRAINING_GUIDE.md)"
    )
    parser.add_argument(
        "--background-sample-rate",
        type=float,
        default=0.01,
        help="Sample rate for non-promoted events (0.0-1.0, default: 0.01 = 1%%)"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="TCP listener host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5050,
        help="TCP listener port (default: 5050)"
    )
    
    args = parser.parse_args()
    
    # Validate background sample rate
    if not 0.0 <= args.background_sample_rate <= 1.0:
        log.error(f"Invalid background-sample-rate: {args.background_sample_rate} (must be 0.0-1.0)")
        sys.exit(1)
    
    main(
        dataset_dir=args.dataset_dir,
        label_file=args.label_file,
        background_sample_rate=args.background_sample_rate,
        host=args.host,
        port=args.port,
    )

