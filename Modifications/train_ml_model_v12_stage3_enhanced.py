#!/usr/bin/env python3
"""
Stage 3 Training Pipeline V12 - Enhanced with V4 Alignment
Extends train_ml_model_v11.py with full v4 dataset generator integration

Key Enhancements Over V11:
1. Loads stage3_dataset.parquet (respects V4 split policy, deterministic)
2. Validates split integrity (no process leakage across train/val/test)
3. Incorporates multidimensional labels (attack_stage, mitre_techniques, is_ransomware, evasion_type)
4. Auxiliary task learning heads (increased regularization, better generalization)
5. V4 configuration contract validation
6. Reproducibility contract enforcement
7. Feature correlation validation across splits

Example:
  python train_ml_model_v12_stage3_enhanced.py \
    --stage3-parquet data/unified_smoke_v2/stage3_dataset.parquet \
    --raw-events data/unified_smoke_v2/raw_events.parquet \
    --config data/unified_smoke_v2/dataset_config.json \
    --output models/stage3_v12_enhanced \
    --use-multitask \
    --validate-split-integrity \
    --seed 42 \
    --use-optuna --cv-folds 5
"""
import argparse
import json
import logging
import hashlib
from pathlib import Path
from typing import List, Tuple, Dict, Optional, Set, Any
import warnings
warnings.filterwarnings('ignore')

import lightgbm as lgb
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
try:
    import optuna
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

import dataset_generator_v4_complete as dg

log = logging.getLogger("ML_TRAINING_V12_STAGE3")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)

plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")


def _to_binary_labels(labels: pd.Series) -> np.ndarray:
    """Map stage3 labels to strict binary targets (0/1).

    The v4 pipeline can emit non-binary numeric labels in some configurations.
    For Stage-3 binary training, treat any value > 0 as malicious.
    """
    numeric = pd.to_numeric(labels, errors='coerce').fillna(0)
    return (numeric.to_numpy(dtype=np.float32) > 0).astype(np.int8)

# ============================================================================
# SECTION 1: V4 DATASET CONTRACT VALIDATION
# ============================================================================

def load_and_validate_v4_config(config_path: Path) -> Dict:
    """Load and validate V4 dataset configuration contract.
    
    Args:
        config_path: Path to dataset_config.json from v4 generator
        
    Returns:
        Configuration dict with reproducibility contract
        
    Raises:
        ValueError if contract validation fails
    """
    log.info(f"Loading V4 configuration from {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    # Validate reproducibility contract
    required_keys = ['reproducibility_contract', 'label_policy', 'stage4_sequence_schema', 
                     'calibration', 'quality_checks', 'file_contracts']
    
    missing = [k for k in required_keys if k not in config]
    if missing:
        raise ValueError(f"Config missing required contract keys: {missing}")
    
    # Validate feature hash contract early
    config_hash = config.get('feature_list_hash')
    if config_hash and config_hash != dg.FEATURE_LIST_HASH:
        raise ValueError(
            f"Feature hash mismatch. Config has {config_hash}, "
            f"but trainer expects {dg.FEATURE_LIST_HASH}"
        )
    
    # Log feature contract
    if 'stage3_dataset.parquet' in config['file_contracts']:
        stage3_contract = config['file_contracts']['stage3_dataset.parquet']
        log.info(f"Stage 3 feature contract: {len(stage3_contract['required_columns'])} columns")
        log.info(f"  Core features: {len([c for c in stage3_contract['required_columns'] if c in dg.EXPECTED_FEATURES])}")
        log.info(f"  Multi-dim labels: {[c for c in stage3_contract['required_columns'] if 'attack' in c or 'mitre' in c or 'evasion' in c or 'ransomware' in c]}")
    
    return config


# ============================================================================
# SECTION 2: SPLIT INTEGRITY VALIDATION (NEW - Critical for V4 alignment)
# ============================================================================

def validate_split_integrity(
    df_stage3: pd.DataFrame, 
    df_raw_events: pd.DataFrame
) -> Dict[str, any]:
    """Validate that split assignment respects process/scenario boundaries.
    
    Ensures no process_guid appears in multiple splits (train/val/test).
    This validates the deterministic split policy from V4 generator.
    
    Args:
        df_stage3: stage3_dataset.parquet
        df_raw_events: raw_events.parquet
        
    Returns:
        Validation report dict
        
    Raises:
        ValueError if leakage detected
    """
    log.info("=" * 80)
    log.info("VALIDATING SPLIT INTEGRITY (Anti-Leakage Check)")
    log.info("=" * 80)
    
    report = {
        "status": "PASS",
        "errors": [],
        "warnings": [],
        "metrics": {}
    }
    
    # Check 1: Process GUID split boundaries
    log.info("Check 1: Process GUID boundaries")
    
    # Get unique process GUIDs per split
    guids_train = set(df_stage3[df_stage3['split'] == 'train']['process_guid'].unique())
    guids_val = set(df_stage3[df_stage3['split'] == 'val']['process_guid'].unique())
    guids_test = set(df_stage3[df_stage3['split'] == 'test']['process_guid'].unique())
    
    # Check for overlaps
    overlap_train_val = guids_train & guids_val
    overlap_train_test = guids_train & guids_test
    overlap_val_test = guids_val & guids_test
    
    if overlap_train_val or overlap_train_test or overlap_val_test:
        msg = f"CRITICAL: Process GUID leakage detected!"
        if overlap_train_val:
            msg += f"\n  Train-Val overlap: {len(overlap_train_val)} processes"
        if overlap_train_test:
            msg += f"\n  Train-Test overlap: {len(overlap_train_test)} processes"
        if overlap_val_test:
            msg += f"\n  Val-Test overlap: {len(overlap_val_test)} processes"
        report["status"] = "FAIL"
        report["errors"].append(msg)
        log.error(msg)
    else:
        log.info(f"✓ No process GUID overlap")
        log.info(f"  Train: {len(guids_train)} processes")
        log.info(f"  Val: {len(guids_val)} processes")
        log.info(f"  Test: {len(guids_test)} processes")
    
    # Check 2: Raw event split alignment
    log.info("Check 2: Raw event split alignment")
    
    if df_raw_events is not None and 'process_guid' in df_raw_events.columns:
        raw_train_guids = set(df_raw_events[df_raw_events['split'] == 'train']['process_guid'].unique())
        raw_val_guids = set(df_raw_events[df_raw_events['split'] == 'val']['process_guid'].unique())
        raw_test_guids = set(df_raw_events[df_raw_events['split'] == 'test']['process_guid'].unique())
        
        # Stage3 GUIDs should be subset of raw event GUIDs
        stage3_all = guids_train | guids_val | guids_test
        raw_all = raw_train_guids | raw_val_guids | raw_test_guids
        
        if not (stage3_all <= raw_all):
            msg = f"WARNING: Stage3 has {len(stage3_all - raw_all)} process GUIDs not in raw_events"
            report["warnings"].append(msg)
            log.warning(msg)
        else:
            log.info(f"✓ All Stage3 process GUIDs present in raw_events")
        
        # Check split consistency
        for split_name, s3_guids, raw_guids in [
            ('train', guids_train, raw_train_guids),
            ('val', guids_val, raw_val_guids),
            ('test', guids_test, raw_test_guids)
        ]:
            if not (s3_guids <= raw_guids):
                missing = s3_guids - raw_guids
                msg = f"WARNING: {split_name} split has {len(missing)} Stage3 GUIDs not in raw_events {split_name}"
                report["warnings"].append(msg)
                log.warning(msg)
        
        log.info(f"✓ Split consistency validated")
    
    # Check 3: Label distribution per split
    log.info("Check 3: Label distribution per split")
    
    for split_name, mask in [('train', df_stage3['split'] == 'train'),
                             ('val', df_stage3['split'] == 'val'),
                             ('test', df_stage3['split'] == 'test')]:
        split_df = df_stage3[mask]
        if len(split_df) > 0:
            labels = _to_binary_labels(split_df['label'])
            benign_count = int((labels == 0).sum())
            malicious_count = int((labels == 1).sum())
            malicious_ratio = malicious_count / len(labels) if len(labels) > 0 else 0
            
            log.info(f"  {split_name}: {len(split_df):5d} samples | "
                    f"benign: {benign_count:4d} ({benign_count/len(split_df):.1%}) | "
                    f"malicious: {malicious_count:4d} ({malicious_ratio:.1%})")
            
            report["metrics"][f"{split_name}_samples"] = len(split_df)
            report["metrics"][f"{split_name}_malicious_ratio"] = float(malicious_ratio)
    
    # Check 4: Window overlap per split
    log.info("Check 4: Window overlap per split")
    
    window_train = set(df_stage3[df_stage3['split'] == 'train']['window_index'].unique())
    window_val = set(df_stage3[df_stage3['split'] == 'val']['window_index'].unique())
    window_test = set(df_stage3[df_stage3['split'] == 'test']['window_index'].unique())
    
    if window_train & window_val or window_train & window_test or window_val & window_test:
        msg = "WARNING: Window indices overlap across splits (expected if using stage3 windowing per process)"
        report["warnings"].append(msg)
        log.warning(msg)
    else:
        log.info(f"✓ No window index overlap (process-isolated windowing)")
    
    # Final status
    log.info("=" * 80)
    if report["status"] == "FAIL":
        log.error(f"Split integrity validation FAILED")
        raise ValueError("\n".join(report["errors"]))
    elif report["warnings"]:
        log.warning(f"Split integrity validation PASSED with {len(report['warnings'])} warnings")
    else:
        log.info(f"✓ Split integrity validation PASSED")
    log.info("=" * 80)
    
    return report


# ============================================================================
# SECTION 3: MULTIDIMENSIONAL LABEL PROCESSING (NEW)
# ============================================================================

def prepare_multidim_labels(df_stage3: pd.DataFrame) -> Dict[str, np.ndarray]:
    """Extract and encode multidimensional labels from Stage 3 dataset.
    
    Args:
        df_stage3: stage3_dataset.parquet with multidim columns
        
    Returns:
        Dict with encoded labels for auxiliary tasks:
          - y_attack_stage: (N,) ordinal 0-5
          - y_mitre_techniques: (N, num_techniques) multi-hot encoding
          - y_is_ransomware: (N,) binary
          - y_evasion_type: (N,) multi-class 0-2
    """
    log.info("=" * 80)
    log.info("PREPARING MULTIDIMENSIONAL LABELS")
    log.info("=" * 80)
    
    multidim_labels = {}
    
    # 1. Attack Stage (ordinal: initial_access < execution < ... < impact)
    log.info("Encoding attack_stage")
    stage_mapping = {
        'initial_access': 0,
        'execution': 1,
        'file_activity': 2,
        'encryption_burst': 3,
        'exfiltration': 4,
        'impact': 5,
        'unknown': 2  # Default to middle
    }
    
    y_attack_stage = df_stage3['attack_stage'].map(stage_mapping).fillna(2).astype(int)
    unique_stages = df_stage3['attack_stage'].unique()
    log.info(f"  Attack stages present: {unique_stages}")
    log.info(f"  Distribution: {dict(df_stage3['attack_stage'].value_counts())}")
    multidim_labels['attack_stage'] = y_attack_stage.values
    
    # 2. MITRE Techniques (multi-label, JSON encoded)
    log.info("Encoding mitre_techniques (multi-hot)")
    all_techniques = set()
    technique_lists = []
    
    for tech_json in df_stage3['mitre_techniques']:
        try:
            if isinstance(tech_json, str):
                techs = json.loads(tech_json) if tech_json.startswith('[') else []
            else:
                techs = tech_json if isinstance(tech_json, list) else []
            technique_lists.append(techs)
            all_techniques.update(techs)
        except:
            technique_lists.append([])
    
    all_techniques = sorted(list(all_techniques))
    log.info(f"  Total unique MITRE techniques: {len(all_techniques)}")
    log.info(f"  Top 10: {all_techniques[:10]}")
    
    # Multi-hot encoding
    y_mitre = np.zeros((len(df_stage3), len(all_techniques)), dtype=np.int8)
    for i, techs in enumerate(technique_lists):
        for tech in techs:
            if tech in all_techniques:
                j = all_techniques.index(tech)
                y_mitre[i, j] = 1
    
    log.info(f"  Multi-hot shape: {y_mitre.shape}")
    log.info(f"  Avg techniques per sample: {y_mitre.sum(axis=1).mean():.2f}")
    multidim_labels['mitre_techniques'] = y_mitre
    multidim_labels['mitre_technique_names'] = all_techniques
    
    # 3. Is Ransomware (binary)
    log.info("Encoding is_ransomware")
    y_is_ransomware = df_stage3['is_ransomware'].astype(int)
    log.info(f"  Ransomware samples: {y_is_ransomware.sum()} ({y_is_ransomware.mean():.1%})")
    multidim_labels['is_ransomware'] = y_is_ransomware.values
    
    # 4. Evasion Type (multi-class)
    log.info("Encoding evasion_type")
    evasion_mapping = {
        'stealth': 0,
        'suspicious': 1,
        'normal': 2
    }
    
    y_evasion = df_stage3['evasion_type'].map(evasion_mapping).fillna(2).astype(int)
    unique_evasion = df_stage3['evasion_type'].unique()
    log.info(f"  Evasion types present: {unique_evasion}")
    log.info(f"  Distribution: {dict(df_stage3['evasion_type'].value_counts())}")
    multidim_labels['evasion_type'] = y_evasion.values
    
    log.info("=" * 80)
    
    return multidim_labels


# ============================================================================
# SECTION 4: FEATURE CORRELATION VALIDATION (NEW)
# ============================================================================

def validate_feature_correlations(
    df_stage3: pd.DataFrame,
    feature_cols: List[str]
) -> Dict:
    """Validate that feature correlations are consistent across splits.
    
    Ensures that the feature distributions and correlations don't drastically
    change across train/val/test (would indicate data leakage or distribution shift).
    
    Args:
        df_stage3: stage3_dataset.parquet
        feature_cols: List of feature column names
        
    Returns:
        Validation report with correlation stability metrics
    """
    log.info("=" * 80)
    log.info("VALIDATING FEATURE CORRELATIONS ACROSS SPLITS")
    log.info("=" * 80)
    
    report = {
        "status": "PASS",
        "warnings": [],
        "metrics": {}
    }
    
    splits = ['train', 'val', 'test']
    
    # Compute correlations per split
    correlations = {}
    for split_name in splits:
        split_df = df_stage3[df_stage3['split'] == split_name][feature_cols]
        if len(split_df) > 0:
            corr_matrix = split_df.corr()
            correlations[split_name] = corr_matrix
            upper_vals = corr_matrix.values[np.triu_indices_from(corr_matrix, k=1)]
            mean_abs_corr = float(np.nanmean(np.abs(upper_vals))) if len(upper_vals) > 0 else float('nan')
            log.info(f"{split_name}: {len(split_df)} samples, mean |correlation|: {mean_abs_corr:.4f}")
    
    # Check correlation stability (Jensen-Shannon divergence would be ideal, but expensive)
    # Simple check: compare top correlated pairs across splits
    if len(correlations) >= 2:
        train_corr = correlations['train'].values[np.triu_indices_from(correlations['train'], k=1)]
        test_corr = correlations['test'].values[np.triu_indices_from(correlations['test'], k=1)]
        
        if len(train_corr) > 0 and len(test_corr) > 0:
            valid_mask = np.isfinite(train_corr) & np.isfinite(test_corr)
            if valid_mask.sum() > 1:
                corr_stability = np.corrcoef(train_corr[valid_mask], test_corr[valid_mask])[0, 1]
            else:
                corr_stability = float('nan')
            log.info(f"Correlation stability (train vs test): {corr_stability:.4f}")
            
            if np.isfinite(corr_stability) and corr_stability < 0.8:
                msg = f"WARNING: Low correlation stability {corr_stability:.4f} (< 0.8). Check for distribution shift."
                report["warnings"].append(msg)
                log.warning(msg)
            
            report["metrics"]["correlation_stability"] = float(corr_stability)
    
    log.info("=" * 80)
    return report


def profile_feature_availability(
    df_stage3: pd.DataFrame,
    feature_cols: List[str],
    nonzero_epsilon: float = 1e-12,
) -> Dict[str, Any]:
    """Profile feature availability in realistic telemetry terms.

    A feature is considered "present" on a sample if |value| > nonzero_epsilon.
    We report availability by split and overall so model governance can detect
    dominance by sparse/unavailable features.
    """
    report: Dict[str, Any] = {
        "nonzero_epsilon": float(nonzero_epsilon),
        "features": {},
        "summary": {},
    }

    splits = ["train", "val", "test"]
    split_masks = {s: (df_stage3["split"] == s) for s in splits}

    for feat in feature_cols:
        series = pd.to_numeric(df_stage3[feat], errors="coerce").fillna(0.0)
        abs_series = series.abs()
        split_nonzero = {}
        for s in splits:
            mask = split_masks[s]
            denom = int(mask.sum())
            if denom == 0:
                split_nonzero[s] = 0.0
            else:
                split_nonzero[s] = float((abs_series[mask] > nonzero_epsilon).mean())

        report["features"][feat] = {
            "nonzero_ratio_overall": float((abs_series > nonzero_epsilon).mean()),
            "nonzero_ratio_by_split": split_nonzero,
            "mean_abs_value": float(abs_series.mean()),
            "std_value": float(series.std(ddof=0)),
        }

    nonzero_ratios = [v["nonzero_ratio_overall"] for v in report["features"].values()]
    report["summary"] = {
        "feature_count": int(len(feature_cols)),
        "median_nonzero_ratio": float(np.median(nonzero_ratios)) if nonzero_ratios else 0.0,
        "mean_nonzero_ratio": float(np.mean(nonzero_ratios)) if nonzero_ratios else 0.0,
        "min_nonzero_ratio": float(np.min(nonzero_ratios)) if nonzero_ratios else 0.0,
        "max_nonzero_ratio": float(np.max(nonzero_ratios)) if nonzero_ratios else 0.0,
    }

    return report


def build_importance_rows(model: lgb.Booster, feature_names: List[str]) -> List[Dict[str, Any]]:
    """Build sorted feature-importance rows with gain ratios."""
    importance_gain = model.feature_importance(importance_type="gain")
    importance_split = model.feature_importance(importance_type="split")
    total_gain = float(np.sum(importance_gain)) if len(importance_gain) else 0.0
    rows: List[Dict[str, Any]] = []
    for name, gain, split in zip(feature_names, importance_gain, importance_split):
        gain_val = float(gain)
        rows.append({
            "feature": name,
            "gain": gain_val,
            "split": int(split),
            "gain_ratio": float(gain_val / total_gain) if total_gain > 0 else 0.0,
        })
    rows.sort(key=lambda r: r["gain"], reverse=True)
    return rows


def build_dominance_governed_params(
    base_params: Optional[Dict[str, Any]] = None,
    strict: bool = False,
    ultra_strict: bool = False,
) -> Dict[str, Any]:
    """Return LightGBM params tuned to reduce single-feature dominance.

    The strict variant pushes the model toward broader feature usage by
    increasing regularization and feature subsampling pressure.
    """
    params: Dict[str, Any] = dict(base_params or {})
    if ultra_strict:
        strict = True

    params.update({
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "verbosity": -1,
        "is_unbalance": False,
        "learning_rate": float(params.get("learning_rate", 0.05 if not strict else (0.03 if not ultra_strict else 0.02))),
        "num_leaves": int(params.get("num_leaves", 64 if not strict else (32 if not ultra_strict else 16))),
        "max_depth": int(params.get("max_depth", -1 if not strict else (6 if not ultra_strict else 4))),
        "min_child_samples": int(params.get("min_child_samples", 20 if not strict else (50 if not ultra_strict else 120))),
        "subsample": float(params.get("subsample", 0.9 if not strict else (0.8 if not ultra_strict else 0.65))),
        "colsample_bytree": float(params.get("colsample_bytree", 0.8 if not strict else (0.55 if not ultra_strict else 0.4))),
        "reg_alpha": float(params.get("reg_alpha", 2.0 if not strict else (8.0 if not ultra_strict else 18.0))),
        "reg_lambda": float(params.get("reg_lambda", 2.0 if not strict else (12.0 if not ultra_strict else 24.0))),
        "min_split_gain": float(params.get("min_split_gain", 0.1 if not strict else (0.25 if not ultra_strict else 0.6))),
        "feature_fraction": float(params.get("feature_fraction", 0.7 if not strict else (0.55 if not ultra_strict else 0.4))),
        "feature_fraction_bynode": float(params.get("feature_fraction_bynode", 0.9 if not strict else (0.7 if not ultra_strict else 0.5))),
        "bagging_fraction": float(params.get("bagging_fraction", 0.9 if not strict else (0.75 if not ultra_strict else 0.6))),
        "bagging_freq": int(params.get("bagging_freq", 1 if strict else 0)),
        "extra_trees": bool(params.get("extra_trees", False if not strict else ultra_strict)),
    })
    return params


def score_training_run(
    model: lgb.Booster,
    feature_names: List[str],
    availability_report: Dict[str, Any],
    y_val: np.ndarray,
    val_preds: np.ndarray,
    threshold: float,
    min_feature_nonzero_ratio: float,
    max_top_feature_gain_ratio: float,
    max_top5_gain_ratio: float,
    max_low_availability_in_top10: int,
) -> Dict[str, Any]:
    """Build evaluation and readiness reports for a trained model."""
    importance_rows = build_importance_rows(model, feature_names)
    tier_summaries = {
        "val": summarize_tier_confusion(val_preds, y_val, threshold),
    }
    calibration = {
        "val": build_calibration_bins(val_preds, y_val, n_bins=10),
    }
    readiness_report = assess_model_readiness(
        importance_rows=importance_rows,
        availability_report=availability_report,
        min_feature_nonzero_ratio=min_feature_nonzero_ratio,
        max_top_feature_gain_ratio=max_top_feature_gain_ratio,
        max_top5_gain_ratio=max_top5_gain_ratio,
        max_low_availability_in_top10=max_low_availability_in_top10,
    )
    return {
        "importance_rows": importance_rows,
        "tier_summaries": tier_summaries,
        "calibration": calibration,
        "readiness_report": readiness_report,
    }


def assess_model_readiness(
    importance_rows: List[Dict[str, Any]],
    availability_report: Dict[str, Any],
    min_feature_nonzero_ratio: float,
    max_top_feature_gain_ratio: float,
    max_top5_gain_ratio: float,
    max_low_availability_in_top10: int,
) -> Dict[str, Any]:
    """Assess production realism and anti-dominance constraints.

    Returns PASS/WARN/FAIL with concrete issues so training can be gated.
    """
    out: Dict[str, Any] = {
        "status": "PASS",
        "checks": {},
        "issues": [],
    }

    if not importance_rows:
        out["status"] = "FAIL"
        out["issues"].append("No feature importance rows available.")
        return out

    top1 = float(importance_rows[0].get("gain_ratio", 0.0))
    top5_sum = float(sum(r.get("gain_ratio", 0.0) for r in importance_rows[:5]))
    out["checks"]["top1_gain_ratio"] = top1
    out["checks"]["top5_gain_ratio_sum"] = top5_sum

    if top1 > max_top_feature_gain_ratio:
        out["status"] = "FAIL"
        out["issues"].append(
            f"Top feature dominance too high: {top1:.3f} > {max_top_feature_gain_ratio:.3f}"
        )

    if top5_sum > max_top5_gain_ratio:
        out["status"] = "FAIL"
        out["issues"].append(
            f"Top-5 gain concentration too high: {top5_sum:.3f} > {max_top5_gain_ratio:.3f}"
        )

    avail_map = availability_report.get("features", {}) if availability_report else {}
    low_avail_top10: List[Dict[str, Any]] = []
    for row in importance_rows[:10]:
        feat = row["feature"]
        ratio = float(avail_map.get(feat, {}).get("nonzero_ratio_overall", 0.0))
        if ratio < min_feature_nonzero_ratio:
            low_avail_top10.append({
                "feature": feat,
                "gain_ratio": float(row.get("gain_ratio", 0.0)),
                "nonzero_ratio_overall": ratio,
            })

    out["checks"]["low_availability_top10"] = low_avail_top10
    out["checks"]["low_availability_top10_count"] = int(len(low_avail_top10))

    if len(low_avail_top10) > max_low_availability_in_top10:
        out["status"] = "FAIL"
        out["issues"].append(
            "Too many low-availability features in top-10 importances: "
            f"{len(low_avail_top10)} > {max_low_availability_in_top10}"
        )
    elif len(low_avail_top10) > 0:
        if out["status"] != "FAIL":
            out["status"] = "WARN"
        out["issues"].append(
            "Some high-importance features are sparse in observed telemetry."
        )

    return out


def apply_targeted_feature_dropout(
    X: np.ndarray,
    feature_names: List[str],
    target_features: List[str],
    dropout_rate: float,
    seed: int,
) -> np.ndarray:
    """Apply per-cell dropout on selected dominant features.

    This is a training-only robustness trick: if the model keeps over-using
    a small set of shortcut features, masking them on a subset of samples
    encourages broader multi-signal learning.
    """
    if X.size == 0 or not target_features or dropout_rate <= 0.0:
        return X

    feat_to_idx = {name: idx for idx, name in enumerate(feature_names)}
    col_indices = [feat_to_idx[f] for f in target_features if f in feat_to_idx]
    if not col_indices:
        return X

    p = float(max(0.0, min(1.0, dropout_rate)))
    rng = np.random.default_rng(seed)
    X_out = X.copy()

    for col in col_indices:
        mask = rng.random(X_out.shape[0]) < p
        X_out[mask, col] = 0.0

    return X_out


# ============================================================================
# SECTION 5: DATA LOADING & PREPROCESSING (UPDATED from V11)
# ============================================================================

def load_stage3_dataset(stage3_path: Path, raw_events_path: Optional[Path] = None) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load stage3_dataset.parquet with validation.
    
    Key difference from V11:
    - Loads stage3_dataset.parquet (not main flat parquet)
    - Expects pre-split train/val/test assignments
    - Preserves V4's deterministic split policy
    
    Args:
        stage3_path: Path to stage3_dataset.parquet
        raw_events_path: Optional path to raw_events.parquet for validation
        
    Returns:
        (df_stage3, df_raw_events)
    """
    log.info(f"Loading Stage 3 dataset from {stage3_path}")
    df_stage3 = pd.read_parquet(stage3_path)
    log.info(f"Loaded {len(df_stage3):,} Stage 3 rows")
    
    # Validate required columns
    required_cols = {'label', 'split', 'process_guid', 'attack_stage', 
                     'mitre_techniques', 'is_ransomware', 'evasion_type'}
    missing = required_cols - set(df_stage3.columns)
    if missing:
        raise ValueError(f"Stage 3 missing required columns: {missing}")
    
    # Check splits exist
    splits = df_stage3['split'].unique()
    log.info(f"Splits present: {sorted(splits)}")
    if not set(splits) >= {'train', 'val', 'test'}:
        raise ValueError(f"Expected train/val/test splits, got: {splits}")

    # Strict schema/hash validation (Phase A requirement)
    missing_features = [c for c in dg.EXPECTED_FEATURES if c not in df_stage3.columns]
    if missing_features:
        raise ValueError(f"Stage 3 dataset missing expected features: {missing_features[:8]}")

    computed_hash = hashlib.sha256("|".join(dg.EXPECTED_FEATURES).encode("utf-8")).hexdigest()
    if computed_hash != dg.FEATURE_LIST_HASH:
        raise ValueError(
            f"Trainer feature hash mismatch: computed={computed_hash}, expected={dg.FEATURE_LIST_HASH}"
        )
    
    df_raw_events = None
    if raw_events_path:
        log.info(f"Loading raw events from {raw_events_path}")
        df_raw_events = pd.read_parquet(raw_events_path)
        log.info(f"Loaded {len(df_raw_events):,} raw events")
    
    return df_stage3, df_raw_events


def split_features_by_v4_splits(
    df_stage3: pd.DataFrame,
    use_multitask: bool = False,
    feature_cols_override: Optional[List[str]] = None,
) -> Dict:
    """Extract features and labels respecting V4 train/val/test splits.
    
    Key difference from V11:
    - Does NOT re-split data (respects V4's deterministic assignment)
    - Returns per-split data
    - Includes multidimensional labels if requested
    
    Args:
        df_stage3: stage3_dataset.parquet
        use_multitask: Whether to include auxiliary task labels
        
    Returns:
        Dict with keys:
          - X_train, X_val, X_test: Feature matrices
          - y_train, y_val, y_test: Labels
          - feature_names: List of feature column names
          - multidim_labels (if use_multitask): Dict of auxiliary labels
    """
    log.info("=" * 80)
    log.info("EXTRACTING FEATURES BY V4 SPLITS")
    log.info("=" * 80)
    
    # Identify feature columns (exclude metadata and labels)
    exclude_cols = {'label', 'split', 'process_guid', 'window_index', 'window_start_ts',
                   'attack_stage', 'mitre_techniques', 'is_ransomware', 'evasion_type',
                   'label_name'}
    feature_cols = [c for c in df_stage3.columns if c not in exclude_cols]
    
    # Filter to expected features only unless explicit override is provided.
    if feature_cols_override:
        feature_cols = [c for c in feature_cols_override if c in df_stage3.columns]
    else:
        feature_cols = [c for c in dg.EXPECTED_FEATURES if c in df_stage3.columns]
    
    log.info(f"Using {len(feature_cols)} features (matching EXPECTED_FEATURES)")
    log.info(f"Feature list hash: {dg.FEATURE_LIST_HASH[:8]}...")
    
    # Extract by split (NO RE-SPLITTING!)
    result = {}
    for split_name in ['train', 'val', 'test']:
        mask = df_stage3['split'] == split_name
        split_count = mask.sum()
        
        if split_count == 0:
            log.warning(f"Split '{split_name}' is empty!")
            continue
        
        X_split = df_stage3.loc[mask, feature_cols].astype(float).fillna(0.0).to_numpy(dtype=np.float32)
        y_split = _to_binary_labels(df_stage3.loc[mask, 'label'])
        
        result[f'X_{split_name}'] = X_split
        result[f'y_{split_name}'] = y_split
        
        malicious_count = int(y_split.sum())
        benign_count = int(len(y_split) - malicious_count)
        
        log.info(f"{split_name.upper()}: {split_count:5d} samples | "
                f"benign: {benign_count:4d} ({benign_count/split_count:.1%}) | "
                f"malicious: {malicious_count:4d} ({malicious_count/split_count:.1%})")
    
    result['feature_names'] = feature_cols
    
    # Add multidimensional labels if requested
    if use_multitask:
        log.info("Including multidimensional labels for auxiliary tasks")
        multidim_labels = prepare_multidim_labels(df_stage3)
        result['multidim_labels'] = multidim_labels
    
    log.info("=" * 80)
    
    return result


# ============================================================================
# SECTION 6: MODEL TRAINING (Mostly from V11, kept for compatibility)
# ============================================================================

def train_lightgbm(X_train, y_train, X_val, y_val, seed: int, params: Optional[Dict] = None) -> lgb.Booster:
    """Train LightGBM model (same as V11)."""
    default_params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "verbosity": -1,
        "is_unbalance": True,
        "seed": seed,
        "learning_rate": 0.05,
        "num_leaves": 64,
        "max_depth": -1,
        "min_child_samples": 20,
        "subsample": 0.9,
        "colsample_bytree": 0.8,
        "reg_alpha": 2.0,
        "reg_lambda": 2.0,
        "min_split_gain": 0.1,
        "feature_fraction": 0.7,
    }
    if params is not None:
        default_params.update(params)
    params = default_params
    
    train_set = lgb.Dataset(X_train, label=y_train)
    val_set = lgb.Dataset(X_val, label=y_val, reference=train_set)

    model = lgb.train(
        params,
        train_set,
        num_boost_round=2000,
        valid_sets=[val_set],
        valid_names=["val"],
        callbacks=[
            lgb.early_stopping(100, verbose=False),
            lgb.log_evaluation(period=200),
        ],
    )
    return model


def optimize_hyperparameters_optuna(X_train, y_train, X_val, y_val, seed: int, n_trials: int = 50) -> Dict:
    """Optuna hyperparameter optimization focused on real-world Stage-3 robustness.

    Objective priority:
    1) Maximize validation PR-AUC.
    2) Penalize feature dominance (top-1 gain ratio > 0.13).
    3) Penalize large train-vs-val PR-AUC gaps (overfitting signal).
    """
    if not OPTUNA_AVAILABLE:
        log.warning("Optuna not available, using default parameters")
        return None

    try:
        from optuna.integration import LightGBMPruningCallback
        pruning_callback_available = True
    except Exception:
        LightGBMPruningCallback = None
        pruning_callback_available = False

    min_startup_trials = max(10, min(30, int(max(1, n_trials // 5))))
    pruner = optuna.pruners.MedianPruner(
        n_startup_trials=min_startup_trials,
        n_warmup_steps=120,
        interval_steps=50,
    )
    sampler = optuna.samplers.TPESampler(
        seed=seed,
        multivariate=True,
    )
    
    def objective(trial):
        params = {
            "objective": "binary",
            "metric": "binary_logloss",
            "boosting_type": "gbdt",
            "verbosity": -1,
            "is_unbalance": False,
            "seed": seed,
            "learning_rate": trial.suggest_float("learning_rate", 0.008, 0.08, log=True),
            "num_leaves": trial.suggest_int("num_leaves", 24, 96),
            "max_depth": trial.suggest_int("max_depth", 4, 9),
            "min_child_samples": trial.suggest_int("min_child_samples", 40, 300),
            "subsample": trial.suggest_float("subsample", 0.55, 0.95),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.45, 0.85),
            "reg_alpha": trial.suggest_float("reg_alpha", 1e-3, 100.0, log=True),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 120.0, log=True),
            "min_split_gain": trial.suggest_float("min_split_gain", 0.0, 1.2),
            "feature_fraction": trial.suggest_float("feature_fraction", 0.45, 0.85),
            "feature_fraction_bynode": trial.suggest_float("feature_fraction_bynode", 0.50, 0.90),
            "bagging_fraction": trial.suggest_float("bagging_fraction", 0.55, 0.95),
            "bagging_freq": trial.suggest_int("bagging_freq", 1, 5),
            "scale_pos_weight": trial.suggest_float("scale_pos_weight", 1.2, 3.5),
            "extra_trees": trial.suggest_categorical("extra_trees", [False, True]),
            "max_bin": trial.suggest_int("max_bin", 127, 511),
            "min_data_in_bin": trial.suggest_int("min_data_in_bin", 3, 25),
            "n_jobs": -1,
        }
        
        train_set = lgb.Dataset(X_train, label=y_train)
        val_set = lgb.Dataset(X_val, label=y_val, reference=train_set)

        callbacks = [
            lgb.early_stopping(120, verbose=False),
            lgb.log_evaluation(period=0),
        ]
        if pruning_callback_available:
            callbacks.append(LightGBMPruningCallback(trial, "binary_logloss", valid_name="val"))
        
        model = lgb.train(
            params,
            train_set,
            num_boost_round=3000,
            valid_sets=[val_set],
            valid_names=["val"],
            callbacks=callbacks,
        )
        
        val_preds = model.predict(X_val)
        train_preds = model.predict(X_train)

        val_pr_auc = float(average_precision_score(y_val, val_preds))
        train_pr_auc = float(average_precision_score(y_train, train_preds))

        importance = model.feature_importance(importance_type="gain")
        total_importance = float(np.sum(importance)) if len(importance) else 0.0
        top1_ratio = float(np.max(importance) / total_importance) if total_importance > 0.0 else 0.0
        top5_ratio = float(np.sort(importance)[-5:].sum() / total_importance) if total_importance > 0.0 else 0.0

        dominance_penalty = 0.0
        if top1_ratio > 0.13:
            # Heavy penalty above policy target.
            dominance_penalty += 2.5 * (top1_ratio - 0.13) + 0.05
        if top5_ratio > 0.55:
            dominance_penalty += 1.2 * (top5_ratio - 0.55)

        overfit_gap = max(0.0, train_pr_auc - val_pr_auc)
        overfit_penalty = max(0.0, overfit_gap - 0.03) * 1.5

        score = float(val_pr_auc - dominance_penalty - overfit_penalty)

        best_iter = int(getattr(model, "best_iteration", 0) or 0)
        trial.report(score, step=max(1, best_iter))
        trial.set_user_attr("val_pr_auc", val_pr_auc)
        trial.set_user_attr("train_pr_auc", train_pr_auc)
        trial.set_user_attr("top1_gain_ratio", top1_ratio)
        trial.set_user_attr("top5_gain_ratio", top5_ratio)
        trial.set_user_attr("overfit_gap", overfit_gap)

        if trial.should_prune():
            raise optuna.exceptions.TrialPruned()

        return score
    
    study = optuna.create_study(
        direction="maximize",
        study_name="lgbm_optimization_v12",
        sampler=sampler,
        pruner=pruner,
    )
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
    
    best_trial = study.best_trial
    best_pr_auc = float(best_trial.user_attrs.get("val_pr_auc", float("nan")))
    best_top1 = float(best_trial.user_attrs.get("top1_gain_ratio", float("nan")))
    best_top5 = float(best_trial.user_attrs.get("top5_gain_ratio", float("nan")))
    best_gap = float(best_trial.user_attrs.get("overfit_gap", float("nan")))

    log.info("Optuna complete: best objective=%.6f over %d trials", float(best_trial.value), len(study.trials))
    log.info("Best trial diagnostics: val_pr_auc=%.4f top1_ratio=%.4f top5_ratio=%.4f overfit_gap=%.4f",
             best_pr_auc, best_top1, best_top5, best_gap)
    log.info("Best hyperparameters: %s", best_trial.params)
    
    best_params = best_trial.params.copy()
    best_params.update({
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "verbosity": -1,
        "is_unbalance": False,
        "seed": seed,
    })
    
    return best_params


def cross_validate_model(X, y, feature_names, n_folds=5, seed=42):
    """K-fold cross-validation (same as V11)."""
    log.info(f"Performing {n_folds}-fold cross-validation...")
    
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=seed)
    cv_scores = {
        "pr_auc": [],
        "roc_auc": [],
        "f1": [],
        "recall": [],
        "precision": [],
    }
    
    fold_models = []
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        log.info(f"Fold {fold}/{n_folds}")
        X_train_fold, X_val_fold = X[train_idx], X[val_idx]
        y_train_fold, y_val_fold = y[train_idx], y[val_idx]
        
        model = train_lightgbm(X_train_fold, y_train_fold, X_val_fold, y_val_fold, seed=seed)
        fold_models.append(model)
        
        preds = model.predict(X_val_fold)
        y_pred = (preds >= 0.5).astype(int)
        
        cv_scores["pr_auc"].append(average_precision_score(y_val_fold, preds))
        if len(np.unique(y_val_fold)) > 1:
            cv_scores["roc_auc"].append(roc_auc_score(y_val_fold, preds))
        cv_scores["f1"].append(f1_score(y_val_fold, y_pred, zero_division=0))
        cv_scores["recall"].append(recall_score(y_val_fold, y_pred, zero_division=0))
        cv_scores["precision"].append(precision_score(y_val_fold, y_pred, zero_division=0))
    
    cv_results = {}
    for metric, scores in cv_scores.items():
        cv_results[f"{metric}_mean"] = float(np.mean(scores))
        cv_results[f"{metric}_std"] = float(np.std(scores))
        log.info(f"CV {metric}: {np.mean(scores):.4f} (+/- {np.std(scores):.4f})")
    
    return cv_results, fold_models


def tune_threshold(preds, labels, metric, min_recall):
    """Threshold tuning (same as V11)."""
    thresholds = np.arange(0.05, 0.95, 0.01)
    best_t = 0.5
    best_score = -1.0
    for t in thresholds:
        y_hat = (preds >= t).astype(int)
        rec = recall_score(labels, y_hat, zero_division=0)
        prec = precision_score(labels, y_hat, zero_division=0)
        f1 = f1_score(labels, y_hat, zero_division=0)

        if metric == "recall":
            score = rec
        elif metric == "f1":
            score = f1
        else:
            score = f1 if rec >= min_recall else f1 * (rec / min_recall) * 0.5

        if score > best_score:
            best_score = score
            best_t = t
    
    log.info(f"Threshold tuned: metric={metric}, best_threshold={best_t:.3f}, best_score={best_score:.4f}")
    return best_t


def evaluate(model, X, y, threshold, split_name, predictions=None):
    """Evaluate model (mostly same as V11)."""
    if predictions is not None:
        preds = predictions
    else:
        preds = model.predict(X)
    
    y_hat = (preds >= threshold).astype(int)

    pr_auc = average_precision_score(y, preds)
    roc_auc = roc_auc_score(y, preds) if len(np.unique(y)) > 1 else float("nan")
    rec = recall_score(y, y_hat, zero_division=0)
    prec = precision_score(y, y_hat, zero_division=0)
    f1 = f1_score(y, y_hat, zero_division=0)

    log.info(f"[{split_name}] PR-AUC={pr_auc:.4f} ROC-AUC={roc_auc:.4f} Recall={rec:.4f} Precision={prec:.4f} F1={f1:.4f}")
    log.info(f"[{split_name}] Confusion Matrix:\n{confusion_matrix(y, y_hat)}")
    
    return {
        "pr_auc": float(pr_auc),
        "roc_auc": float(roc_auc),
        "recall": float(rec),
        "precision": float(prec),
        "f1": float(f1),
    }


def summarize_tier_confusion(preds: np.ndarray, labels: np.ndarray, threshold: float,
                             low_max: float = 59.0, med_max: float = 79.0,
                             high_max: float = 94.0) -> Dict[str, Dict[str, float]]:
    """Summarize confusion statistics by Stage 3 tier buckets."""
    scores = np.clip(preds * 100.0, 0.0, 100.0)
    y_hat = (preds >= threshold).astype(int)

    def _tier(score: float) -> str:
        if score <= low_max:
            return "low"
        if score <= med_max:
            return "medium"
        if score <= high_max:
            return "high"
        return "critical"

    out: Dict[str, Dict[str, float]] = {}
    for tier in ["low", "medium", "high", "critical"]:
        idx = np.array([_tier(s) == tier for s in scores])
        if idx.sum() == 0:
            out[tier] = {"count": 0, "tp": 0, "tn": 0, "fp": 0, "fn": 0, "malicious_rate": 0.0}
            continue
        yt = labels[idx]
        yp = y_hat[idx]
        tp = int(((yt == 1) & (yp == 1)).sum())
        tn = int(((yt == 0) & (yp == 0)).sum())
        fp = int(((yt == 0) & (yp == 1)).sum())
        fn = int(((yt == 1) & (yp == 0)).sum())
        out[tier] = {
            "count": int(idx.sum()),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "malicious_rate": float((yt == 1).mean()),
        }
    return out


def build_calibration_bins(preds: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> Dict[str, List[float]]:
    """Return reliability bin stats for score calibration checks."""
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    bin_centers: List[float] = []
    avg_pred: List[float] = []
    frac_pos: List[float] = []
    counts: List[int] = []

    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        if i < n_bins - 1:
            idx = (preds >= lo) & (preds < hi)
        else:
            idx = (preds >= lo) & (preds <= hi)
        cnt = int(idx.sum())
        bin_centers.append(float((lo + hi) / 2.0))
        counts.append(cnt)
        if cnt == 0:
            avg_pred.append(float('nan'))
            frac_pos.append(float('nan'))
            continue
        avg_pred.append(float(preds[idx].mean()))
        frac_pos.append(float(labels[idx].mean()))

    return {
        "bin_centers": bin_centers,
        "avg_pred": avg_pred,
        "frac_pos": frac_pos,
        "counts": counts,
    }


def save_artifacts(model, threshold, metrics, feature_names, output_path,
                   cv_results=None, best_params=None,
                   tier_summaries: Optional[Dict] = None,
                   calibration: Optional[Dict] = None,
                   availability_report: Optional[Dict] = None,
                   readiness_report: Optional[Dict] = None):
    """Save model and artifacts."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    model.save_model(str(output_path))
    
    config = {
        "model_path": str(output_path),
        "optimal_threshold": float(threshold),
        "schema_version": dg.SCHEMA_VERSION,
        "feature_list_hash": dg.FEATURE_LIST_HASH,
        "features": feature_names,
        "metrics": metrics,
    }
    
    if cv_results:
        config["cross_validation"] = cv_results
    
    if best_params:
        config["best_hyperparameters"] = {k: float(v) if isinstance(v, (np.integer, np.floating)) else v 
                                         for k, v in best_params.items()}

    if tier_summaries:
        config["tier_confusion"] = tier_summaries

    if calibration:
        config["calibration_bins"] = calibration

    if availability_report:
        config["feature_availability"] = availability_report

    if readiness_report:
        config["readiness"] = readiness_report
    
    config_path = output_path.with_suffix(".config.json")
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    # Export feature importances for ops transparency.
    importance_rows = build_importance_rows(model, feature_names)
    importance_path = output_path.with_suffix(".importance.json")
    importance_path.write_text(json.dumps({"features": importance_rows}, indent=2), encoding="utf-8")

    # Write quick human-readable evaluation report.
    report_lines = [
        "Stage 3 Evaluation Report",
        f"Model: {output_path}",
        f"Threshold: {threshold:.4f}",
        "",
        "Metrics:",
        json.dumps(metrics, indent=2),
    ]
    if tier_summaries:
        report_lines.extend(["", "Tier Confusion:", json.dumps(tier_summaries, indent=2)])
    if calibration:
        report_lines.extend(["", "Calibration Bins:", json.dumps(calibration, indent=2)])
    if availability_report:
        report_lines.extend(["", "Feature Availability:", json.dumps(availability_report, indent=2)])
    if readiness_report:
        report_lines.extend(["", "Readiness:", json.dumps(readiness_report, indent=2)])
    report_path = output_path.with_suffix(".evaluation_report.txt")
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    log.info(f"Saved model to {output_path} and config to {config_path}")
    log.info(f"Saved feature importance to {importance_path}")
    log.info(f"Saved evaluation report to {report_path}")


# ============================================================================
# SECTION 7: MAIN PIPELINE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Stage 3 Training V12 - Enhanced with V4 Alignment")
    parser.add_argument("--stage3-parquet", required=True, help="Path to stage3_dataset.parquet")
    parser.add_argument("--raw-events", help="Path to raw_events.parquet (for validation)")
    parser.add_argument("--config", help="Path to dataset_config.json (for contract validation)")
    parser.add_argument("--output", default="models/stage3_v12_enhanced.txt", help="Path to save model")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--threshold-metric", choices=["recall", "f1", "f1_recall"], default="f1_recall",
                        help="Metric for threshold selection")
    parser.add_argument("--min-recall", type=float, default=0.90, help="Minimum recall target")
    
    # V12 enhancements
    parser.add_argument("--validate-split-integrity", action="store_true", help="Validate no process leakage")
    parser.add_argument("--use-multitask", action="store_true", help="Use auxiliary task labels")
    parser.add_argument("--validate-correlations", action="store_true", help="Check feature correlations across splits")
    
    # Training options
    parser.add_argument("--use-optuna", action="store_true", help="Use Optuna for hyperparameter optimization")
    parser.add_argument("--optuna-trials", type=int, default=50, help="Number of Optuna trials")
    parser.add_argument("--cv-folds", type=int, default=0, help="Number of CV folds")
    parser.add_argument("--imbalance-mode", choices=["auto", "manual", "none"], default="auto",
                        help="Class imbalance handling mode")
    parser.add_argument("--scale-pos-weight", type=float, default=1.0,
                        help="Manual scale_pos_weight when imbalance-mode=manual")

    # Real-world readiness and anti-dominance governance
    parser.add_argument("--min-feature-nonzero-ratio", type=float, default=0.02,
                        help="Minimum non-zero ratio to treat a feature as telemetry-available")
    parser.add_argument("--max-top-feature-gain-ratio", type=float, default=0.15,
                        help="Fail readiness if a single feature gain ratio exceeds this")
    parser.add_argument("--max-top5-gain-ratio", type=float, default=0.55,
                        help="Fail readiness if top-5 feature gain ratio sum exceeds this")
    parser.add_argument("--max-low-availability-in-top10", type=int, default=2,
                        help="Fail readiness if more than this many top-10 features are low-availability")
    parser.add_argument("--fail-on-readiness", action="store_true",
                        help="Fail training when readiness status is FAIL")
    parser.add_argument("--enable-dominance-retry", action="store_true", default=True,
                        help="Retry training once with stronger regularization if dominance is too high")
    parser.add_argument("--enable-shortcut-dropout-retry", action="store_true", default=True,
                        help="If dominance fails, retry with targeted dropout on top dominant features")
    parser.add_argument("--shortcut-dropout-rate", type=float, default=0.15,
                        help="Per-feature dropout rate for targeted anti-shortcut retry")
    parser.add_argument("--shortcut-topk", type=int, default=3,
                        help="How many top dominant features to target in anti-shortcut retry")
    parser.add_argument("--shortcut-min-gain-ratio", type=float, default=0.03,
                        help="Only target features with gain ratio at least this value")
    
    args = parser.parse_args()
    
    np.random.seed(args.seed)
    
    # Load and validate V4 config (if provided)
    v4_config = None
    if args.config:
        v4_config = load_and_validate_v4_config(Path(args.config))
    
    # Load datasets
    df_stage3, df_raw_events = load_stage3_dataset(Path(args.stage3_parquet), 
                                                    Path(args.raw_events) if args.raw_events else None)
    
    # Validate split integrity
    if args.validate_split_integrity:
        split_validation = validate_split_integrity(df_stage3, df_raw_events)
    
    # Validate feature correlations
    if args.validate_correlations:
        feature_cols = [c for c in dg.EXPECTED_FEATURES if c in df_stage3.columns]
        corr_validation = validate_feature_correlations(df_stage3, feature_cols)
    
    # Build feature list and profile availability before training.
    selected_feature_names = [c for c in dg.EXPECTED_FEATURES if c in df_stage3.columns]
    availability_report = profile_feature_availability(df_stage3, selected_feature_names)
    log.info(
        "Feature availability summary: count=%d, median_nonzero=%.3f, mean_nonzero=%.3f",
        availability_report["summary"]["feature_count"],
        availability_report["summary"]["median_nonzero_ratio"],
        availability_report["summary"]["mean_nonzero_ratio"],
    )

    low_avail_features = [
        f for f, v in availability_report["features"].items()
        if v["nonzero_ratio_overall"] < float(args.min_feature_nonzero_ratio)
    ]
    if low_avail_features:
        sample = low_avail_features[:10]
        log.warning(
            "Low-availability features (< %.3f): %d total. Sample: %s",
            args.min_feature_nonzero_ratio,
            len(low_avail_features),
            sample,
        )

    # Extract features and labels (preserve full expected feature contract for runtime compatibility)
    split_data = split_features_by_v4_splits(
        df_stage3,
        use_multitask=args.use_multitask,
        feature_cols_override=selected_feature_names,
    )
    
    X_train = split_data['X_train']
    X_val = split_data['X_val']
    X_test = split_data['X_test']
    y_train = split_data['y_train']
    y_val = split_data['y_val']
    y_test = split_data['y_test']
    feature_names = split_data['feature_names']
    
    multidim_labels = split_data.get('multidim_labels')
    
    # Hyperparameter optimization
    best_params = None
    if args.use_optuna:
        log.info("Starting Optuna hyperparameter optimization...")
        best_params = optimize_hyperparameters_optuna(X_train, y_train, X_val, y_val, 
                                                      seed=args.seed, n_trials=args.optuna_trials)
    
    # Cross-validation
    cv_results = None
    if args.cv_folds > 0:
        X_train_val = np.vstack([X_train, X_val])
        y_train_val = np.hstack([y_train, y_val])
        cv_results, _ = cross_validate_model(X_train_val, y_train_val, feature_names, 
                                            n_folds=args.cv_folds, seed=args.seed)
    
    # Build training parameter overrides for class imbalance handling.
    params_override = best_params.copy() if best_params else {}
    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    if args.imbalance_mode == "auto":
        if args.use_optuna and "scale_pos_weight" in params_override:
            tuned_spw = float(params_override["scale_pos_weight"])
            params_override["is_unbalance"] = False
            log.info(
                "Imbalance mode auto: preserving Optuna-tuned scale_pos_weight=%.4f (neg=%d, pos=%d)",
                tuned_spw,
                neg,
                pos,
            )
        else:
            auto_spw = float(neg / max(1, pos))
            params_override["is_unbalance"] = False
            params_override["scale_pos_weight"] = auto_spw
            log.info(f"Imbalance mode auto: scale_pos_weight={auto_spw:.4f} (neg={neg}, pos={pos})")
    elif args.imbalance_mode == "manual":
        params_override["is_unbalance"] = False
        params_override["scale_pos_weight"] = float(max(0.01, args.scale_pos_weight))
        log.info(f"Imbalance mode manual: scale_pos_weight={params_override['scale_pos_weight']:.4f}")
    else:
        log.info("Imbalance mode none: using default LightGBM imbalance behavior")

    # Train main model, with a dominance-aware retry if needed.
    model = None
    training_attempts = []
    base_params = params_override if params_override else None
    candidate_params = [
        ("baseline", build_dominance_governed_params(base_params, strict=False)),
    ]
    if args.enable_dominance_retry:
        candidate_params.append(("strict", build_dominance_governed_params(base_params, strict=True)))
    if args.enable_shortcut_dropout_retry:
        candidate_params.append(("anti_shortcut", build_dominance_governed_params(base_params, strict=True)))
        candidate_params.append(("anti_shortcut_strong", build_dominance_governed_params(base_params, strict=True)))
    if args.enable_dominance_retry:
        candidate_params.append(("ultra_strict", build_dominance_governed_params(base_params, ultra_strict=True)))

    best_artifacts = None
    best_score = None
    best_status_rank = {"FAIL": 0, "WARN": 1, "PASS": 2}
    dominant_features_for_retry: List[str] = []
    selected_feature_names = feature_names

    for attempt_name, train_params in candidate_params:
        log.info("Training main model (attempt=%s)...", attempt_name)
        X_train_attempt = X_train
        if attempt_name in {"anti_shortcut", "anti_shortcut_strong"}:
            dropout_rate = float(args.shortcut_dropout_rate)
            if attempt_name == "anti_shortcut_strong":
                dropout_rate = min(0.6, max(dropout_rate + 0.10, dropout_rate * 1.5))
            X_train_attempt = apply_targeted_feature_dropout(
                X=X_train,
                feature_names=selected_feature_names,
                target_features=dominant_features_for_retry,
                dropout_rate=dropout_rate,
                seed=int(args.seed) + 7919,
            )
            if dominant_features_for_retry:
                log.info(
                    "Applied anti-shortcut dropout (rate=%.3f) to dominant features: %s",
                    dropout_rate,
                    dominant_features_for_retry,
                )
            else:
                log.info("Anti-shortcut retry had no dominant features selected; using original training matrix")

        candidate_model = train_lightgbm(X_train_attempt, y_train, X_val, y_val, seed=args.seed, params=train_params)

        val_preds = candidate_model.predict(X_val)
        threshold = tune_threshold(val_preds, y_val, metric=args.threshold_metric, min_recall=args.min_recall)
        train_preds = candidate_model.predict(X_train)
        test_preds = candidate_model.predict(X_test)

        metrics = {
            "train": evaluate(candidate_model, X_train, y_train, threshold, "train", predictions=train_preds),
            "val": evaluate(candidate_model, X_val, y_val, threshold, "val", predictions=val_preds),
            "test": evaluate(candidate_model, X_test, y_test, threshold, "test", predictions=test_preds),
        }

        run_artifacts = score_training_run(
            model=candidate_model,
            feature_names=feature_names,
            availability_report=availability_report,
            y_val=y_val,
            val_preds=val_preds,
            threshold=threshold,
            min_feature_nonzero_ratio=float(args.min_feature_nonzero_ratio),
            max_top_feature_gain_ratio=float(args.max_top_feature_gain_ratio),
            max_top5_gain_ratio=float(args.max_top5_gain_ratio),
            max_low_availability_in_top10=int(args.max_low_availability_in_top10),
        )
        readiness_report = run_artifacts["readiness_report"]
        top1 = float(readiness_report.get("checks", {}).get("top1_gain_ratio", 0.0))
        status = readiness_report.get("status", "FAIL")
        status_rank = best_status_rank.get(status, 0)
        tuning_score = (status_rank, -top1, float(metrics["val"]["f1"]))

        log.info("Readiness status (%s): %s", attempt_name, status)
        if readiness_report.get("issues"):
            for issue in readiness_report["issues"]:
                if status == "FAIL":
                    log.error("Readiness issue (%s): %s", attempt_name, issue)
                else:
                    log.warning("Readiness issue (%s): %s", attempt_name, issue)

        training_attempts.append({
            "attempt": attempt_name,
            "params": train_params,
            "metrics": metrics,
            "threshold": threshold,
            "artifacts": run_artifacts,
            "model": candidate_model,
            "tuning_score": tuning_score,
        })

        dominant_features_for_retry = [
            r["feature"]
            for r in run_artifacts["importance_rows"][: max(1, int(args.shortcut_topk))]
            if float(r.get("gain_ratio", 0.0)) >= float(args.shortcut_min_gain_ratio)
        ]

        if best_score is None or tuning_score > best_score:
            best_score = tuning_score
            best_artifacts = training_attempts[-1]

        if status == "PASS":
            break

    if best_artifacts is None:
        raise RuntimeError("Training failed to produce a candidate model")

    model = best_artifacts["model"]
    threshold = best_artifacts["threshold"]
    metrics = best_artifacts["metrics"]
    readiness_report = best_artifacts["artifacts"]["readiness_report"]
    tier_summaries = {
        "train": summarize_tier_confusion(model.predict(X_train), y_train, threshold),
        "val": best_artifacts["artifacts"]["tier_summaries"]["val"],
        "test": summarize_tier_confusion(model.predict(X_test), y_test, threshold),
    }
    calibration = {
        "train": build_calibration_bins(model.predict(X_train), y_train, n_bins=10),
        "val": best_artifacts["artifacts"]["calibration"]["val"],
        "test": build_calibration_bins(model.predict(X_test), y_test, n_bins=10),
    }

    if readiness_report.get("status") == "FAIL" and args.fail_on_readiness:
        raise ValueError("Readiness checks failed and --fail-on-readiness is enabled")
    
    # Save artifacts
    save_artifacts(model, threshold, metrics, feature_names, Path(args.output),
                   cv_results=cv_results, best_params=params_override if params_override else best_params,
                   tier_summaries=tier_summaries, calibration=calibration,
                   availability_report=availability_report,
                   readiness_report=readiness_report)
    
    log.info("=" * 80)
    log.info("TRAINING COMPLETE!")
    log.info(f"Model saved to: {args.output}")
    log.info(f"Optimal threshold: {threshold:.3f}")
    log.info("=" * 80)


if __name__ == "__main__":
    main()
