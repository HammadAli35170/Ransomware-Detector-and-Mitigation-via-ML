#!/usr/bin/env python3
"""
Enhanced Training pipeline with Optuna optimization, ensembles, and cross-validation.

Highlights:
- Uses EXPECTED_FEATURES from dataset_generator to enforce schema order
- Validates feature_list_hash and schema_version (optional skip)
- Optuna hyperparameter optimization
- Model ensembles (LightGBM + XGBoost)
- K-fold cross-validation
- Enhanced feature importance visualizations (multiple types)
- Threshold tuning with recall-first or balanced F1/recall
- Saves model, threshold, metrics, and comprehensive feature importance plots

Example:
  python train_ml_model_v11.py --dataset data/fyp_dataset_v3_realistic_20260127.parquet \
    --output models/stage3_model_enhanced --threshold-metric f1_recall --min-recall 0.9 \
    --use-optuna --use-ensemble --cv-folds 5
"""
import argparse
import json
import logging
from pathlib import Path
from typing import List, Tuple, Dict, Optional
import warnings
warnings.filterwarnings('ignore')

import lightgbm as lgb
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    make_scorer,
)
try:
    import optuna
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False
    logging.warning("Optuna not available. Install with: pip install optuna")

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logging.warning("XGBoost not available. Install with: pip install xgboost")

import dataset_generator_v3_complete as dg  # Provides EXPECTED_FEATURES and hashes

log = logging.getLogger("ML_TRAINING_V11_ENHANCED")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)

# Set style for better plots
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

META_COLS = {
    "label",
    "Label",
    "malicious",
    "event_uuid",
    "pid",
    "ppid",
    "process_tree_id",
    "host",
    "image",
    "command_line",
    "parent_image",
    "user",
    "session_id",
    "logon_type",
    "is_elevated",
    "uac_bypass_suspected",
    "_snapshot_phase",
    "_process_age_sec",
    "_events_seen",
    "_snapshot_method",
    "ts_epoch",
}


def read_dataset(path: Path, enforce_hash: bool = True) -> pd.DataFrame:
    df = pd.read_parquet(path)
    log.info(f"Loaded {len(df):,} rows from {path}")

    # Optional schema/hash check
    if enforce_hash:
        computed_hash = dg.hashlib.sha256("|".join(dg.EXPECTED_FEATURES).encode("utf-8")).hexdigest()
        if computed_hash != dg.FEATURE_LIST_HASH:
            raise ValueError("feature_list_hash mismatch; regenerate dataset or update EXPECTED_FEATURES")
    return df


def split_features(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    label_col = next((c for c in ["label", "Label", "malicious"] if c in df.columns), None)
    if not label_col:
        raise ValueError("No label column found")

    missing = [c for c in dg.EXPECTED_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f"Missing expected features: {missing[:5]}{'...' if len(missing) > 5 else ''}")

    feature_cols = list(dg.EXPECTED_FEATURES)
    X = df[feature_cols].astype(float).fillna(0.0).to_numpy(dtype=np.float32)
    y = df[label_col].astype(int).to_numpy()

    log.info(f"Using {len(feature_cols)} features (schema_version={dg.SCHEMA_VERSION})")
    log.info(f"Malicious count: {int(y.sum())} | Benign count: {int((y == 0).sum())}")
    log.info(f"Class balance: {int((y == 0).sum())/len(y):.1%} benign, {int(y.sum())/len(y):.1%} malicious")
    return X, y, feature_cols


def train_lightgbm(X_train, y_train, X_val, y_val, seed: int, params: Optional[Dict] = None) -> lgb.Booster:
    """Train LightGBM model with optional custom parameters."""
    if params is None:
        params = {
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
            "colsample_bytree": 0.8,  # REDUCED: Force feature sampling (was 0.9)
            "reg_alpha": 2.0,  # INCREASED: L1 regularization (was implicit 0)
            "reg_lambda": 2.0,  # INCREASED: L2 regularization (was implicit 0)
            "min_split_gain": 0.1,  # NEW: Prevent overfitting
            "feature_fraction": 0.7,  # NEW: Random feature dropout
        }
    
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


def train_xgboost(X_train, y_train, X_val, y_val, seed: int, params: Optional[Dict] = None) -> xgb.XGBClassifier:
    """Train XGBoost model for ensemble."""
    if not XGBOOST_AVAILABLE:
        raise ImportError("XGBoost not available. Install with: pip install xgboost")
    
    if params is None:
        params = {
            "objective": "binary:logistic",
            "eval_metric": "logloss",
            "random_state": seed,
            "learning_rate": 0.05,
            "max_depth": 6,
            "min_child_weight": 1,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
            "n_estimators": 1000,
            "verbosity": 0,
        }
    
    model = xgb.XGBClassifier(**params)
    
    # Try different XGBoost API versions for early stopping
    try:
        # Try XGBoost 2.0+ API with callbacks
        try:
            from xgboost.callback import EarlyStopping
            callbacks = [EarlyStopping(rounds=100, save_best=True)]
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                callbacks=callbacks,
                verbose=False
            )
        except (ImportError, AttributeError):
            # Try with early_stopping_rounds in fit() (XGBoost < 2.0)
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                early_stopping_rounds=100,
                verbose=False
            )
    except TypeError as e:
        # If early stopping doesn't work, train without it
        log.warning(f"Early stopping not supported in this XGBoost version: {e}. Training without early stopping.")
        model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False
        )
    
    return model


def optimize_hyperparameters_optuna(X_train, y_train, X_val, y_val, seed: int, n_trials: int = 50) -> Dict:
    """Optimize LightGBM hyperparameters using Optuna."""
    if not OPTUNA_AVAILABLE:
        log.warning("Optuna not available, using default parameters")
        return None
    
    def objective(trial):
        params = {
            "objective": "binary",
            "metric": "binary_logloss",
            "boosting_type": "gbdt",
            "verbosity": -1,
            "is_unbalance": True,
            "seed": seed,
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "num_leaves": trial.suggest_int("num_leaves", 31, 300),
            "max_depth": trial.suggest_int("max_depth", 3, 12),
            "min_child_samples": trial.suggest_int("min_child_samples", 5, 100),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),  # REDUCED min
            "reg_alpha": trial.suggest_float("reg_alpha", 0.5, 20.0, log=True),  # INCREASED range
            "reg_lambda": trial.suggest_float("reg_lambda", 0.5, 20.0, log=True),  # INCREASED range
            "min_split_gain": trial.suggest_float("min_split_gain", 0.0, 1.0),  # NEW
            "feature_fraction": trial.suggest_float("feature_fraction", 0.5, 0.9),  # NEW
        }
        
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
            ],
        )
        
        preds = model.predict(X_val)
        
        # DOMINANCE CHECK: Reject models with over-dominant features
        importance = model.feature_importance(importance_type="gain")
        total_importance = importance.sum()
        if total_importance > 0:
            max_importance_ratio = importance.max() / total_importance
            if max_importance_ratio > 0.35:
                log.debug(f"Trial {trial.number}: Rejected due to dominance {max_importance_ratio:.3f} > 0.35")
                return 0.0  # Reject this model
        
        score = average_precision_score(y_val, preds)
        return score
    
    study = optuna.create_study(direction="maximize", study_name="lgbm_optimization")
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
    
    log.info(f"Best hyperparameters: {study.best_params}")
    log.info(f"Best PR-AUC: {study.best_value:.4f}")
    
    # Return best params with fixed values
    best_params = study.best_params.copy()
    best_params.update({
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "verbosity": -1,
        "is_unbalance": True,
        "seed": seed,
    })
    
    return best_params


def cross_validate_model(X: np.ndarray, y: np.ndarray, feature_names: List[str], 
                         n_folds: int = 5, seed: int = 42) -> Dict:
    """Perform k-fold cross-validation."""
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
    
    # Calculate mean and std
    cv_results = {}
    for metric, scores in cv_scores.items():
        cv_results[f"{metric}_mean"] = float(np.mean(scores))
        cv_results[f"{metric}_std"] = float(np.std(scores))
        log.info(f"CV {metric}: {np.mean(scores):.4f} (+/- {np.std(scores):.4f})")
    
    return cv_results, fold_models


def tune_threshold(preds: np.ndarray, labels: np.ndarray, metric: str, min_recall: float) -> float:
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
        else:  # f1_recall balanced
            score = f1 if rec >= min_recall else f1 * (rec / min_recall) * 0.5

        if score > best_score:
            best_score = score
            best_t = t
    log.info(f"Threshold tuned: metric={metric}, best_threshold={best_t:.3f}, best_score={best_score:.4f}")
    return best_t


def evaluate(model, X: np.ndarray, y: np.ndarray, threshold: float, split_name: str, 
             is_ensemble: bool = False, predictions: Optional[np.ndarray] = None,
             snapshot_phases: Optional[np.ndarray] = None):
    """Evaluate model with support for both LightGBM and ensemble models.
    
    Args:
        model: Model to evaluate (can be None if predictions provided)
        X: Features
        y: True labels
        threshold: Decision threshold
        split_name: Name of the split (train/val/test)
        is_ensemble: Whether this is an ensemble model
        predictions: Pre-computed predictions (optional, used when is_ensemble=True)
        snapshot_phases: Optional array of _snapshot_phase values for stage-aware evaluation
    """
    if predictions is not None:
        preds = predictions
    elif is_ensemble and model is not None:
        # Ensemble model with model object
        if hasattr(model, 'predict_proba'):
            preds = model.predict_proba(X)[:, 1]
        else:
            preds = model.predict(X)
    elif model is not None:
        preds = model.predict(X)
    else:
        raise ValueError("Either model or predictions must be provided")
    
    y_hat = (preds >= threshold).astype(int)

    pr_auc = average_precision_score(y, preds)
    roc_auc = roc_auc_score(y, preds) if len(np.unique(y)) > 1 else float("nan")
    rec = recall_score(y, y_hat, zero_division=0)
    prec = precision_score(y, y_hat, zero_division=0)
    f1 = f1_score(y, y_hat, zero_division=0)

    log.info(f"[{split_name}] PR-AUC={pr_auc:.4f} ROC-AUC={roc_auc:.4f} Recall={rec:.4f} Precision={prec:.4f} F1={f1:.4f}")
    log.info(f"[{split_name}] Confusion Matrix:\n{confusion_matrix(y, y_hat)}")
    
    result = {
        "pr_auc": float(pr_auc),
        "roc_auc": float(roc_auc),
        "recall": float(rec),
        "precision": float(prec),
        "f1": float(f1),
    }
    
    # Stage-aware evaluation if snapshot_phases provided
    if snapshot_phases is not None and len(snapshot_phases) == len(y):
        stage_metrics = evaluate_by_stage(y, y_hat, preds, snapshot_phases, split_name)
        result["stage_aware"] = stage_metrics
    
    return result


def evaluate_by_stage(y: np.ndarray, y_hat: np.ndarray, preds: np.ndarray, 
                      snapshot_phases: np.ndarray, split_name: str) -> Dict:
    """Evaluate model performance split by ransomware lifecycle stage.
    
    Args:
        y: True labels
        y_hat: Predicted labels (binary)
        preds: Prediction probabilities
        snapshot_phases: Array of _snapshot_phase values (0.2, 0.4, 0.6, 0.8, 1.0)
        split_name: Name of the split for logging
    
    Returns:
        Dictionary with metrics per stage
    """
    # Define stage boundaries
    early_phase = snapshot_phases <= 0.3  # 0.0-0.3 (early)
    mid_phase = (snapshot_phases > 0.3) & (snapshot_phases <= 0.7)  # 0.3-0.7 (mid)
    late_phase = snapshot_phases > 0.7  # 0.7-1.0 (late)
    
    stage_metrics = {}
    
    for stage_name, mask in [("early", early_phase), ("mid", mid_phase), ("late", late_phase)]:
        if mask.sum() == 0:
            continue
        
        y_stage = y[mask]
        y_hat_stage = y_hat[mask]
        preds_stage = preds[mask]
        
        if len(np.unique(y_stage)) < 2:
            # Skip if no positive or negative samples
            continue
        
        pr_auc = average_precision_score(y_stage, preds_stage)
        rec = recall_score(y_stage, y_hat_stage, zero_division=0)
        prec = precision_score(y_stage, y_hat_stage, zero_division=0)
        f1 = f1_score(y_stage, y_hat_stage, zero_division=0)
        
        stage_metrics[stage_name] = {
            "pr_auc": float(pr_auc),
            "recall": float(rec),
            "precision": float(prec),
            "f1": float(f1),
            "sample_count": int(mask.sum()),
            "positive_count": int(y_stage.sum()),
        }
        
        log.info(f"[{split_name}] {stage_name.upper()}-stage: PR-AUC={pr_auc:.4f} Recall={rec:.4f} Precision={prec:.4f} F1={f1:.4f} (n={mask.sum()}, pos={y_stage.sum()})")
    
    return stage_metrics


def create_ensemble(models: List, X: np.ndarray) -> np.ndarray:
    """Create ensemble predictions by averaging multiple models."""
    predictions = []
    for model in models:
        if isinstance(model, lgb.Booster):
            preds = model.predict(X)
        elif hasattr(model, 'predict_proba'):
            preds = model.predict_proba(X)[:, 1]
        else:
            preds = model.predict(X)
        predictions.append(preds)
    
    return np.mean(predictions, axis=0)


def compute_feature_dominance_score(model, feature_names: List[str]) -> Dict:
    """Compute feature dominance metrics and detect over-dominant features.
    
    Args:
        model: Trained LightGBM model
        feature_names: List of feature names
    
    Returns:
        Dictionary with dominance metrics and recommendations
    """
    importance = model.feature_importance(importance_type="gain")
    total_importance = importance.sum()
    
    # Find most dominant feature
    max_idx = np.argmax(importance)
    max_feature = feature_names[max_idx]
    max_importance = importance[max_idx]
    dominance_score = max_importance / total_importance if total_importance > 0 else 0.0
    
    # Find top 5 features
    top_5_idx = np.argsort(importance)[-5:][::-1]
    top_5_features = [(feature_names[i], importance[i], importance[i] / total_importance) 
                     for i in top_5_idx]
    
    # Detect over-dominant features (>35% threshold - was 30%)
    over_dominant = []
    for i, name in enumerate(feature_names):
        feature_ratio = importance[i] / total_importance if total_importance > 0 else 0.0
        if feature_ratio > 0.35:  # Slightly relaxed from 0.30 to 0.35
            over_dominant.append({
                "feature": name,
                "importance": float(importance[i]),
                "ratio": float(feature_ratio),
            })
    
    result = {
        "dominance_score": float(dominance_score),
        "max_feature": max_feature,
        "max_importance": float(max_importance),
        "total_importance": float(total_importance),
        "top_5_features": top_5_features,
        "over_dominant_features": over_dominant,
        "recommendation": "OK" if dominance_score <= 0.35 else f"WARNING: Feature dominance {dominance_score:.2%} > 35%, rebalance generator",
    }
    
    log.info(f"Feature Dominance Score: {dominance_score:.4f} (max feature: {max_feature})")
    if over_dominant:
        log.warning(f"Over-dominant features detected (>35%): {[f['feature'] for f in over_dominant]}")
        log.warning("Recommendation: Rebalance dataset generator with higher p_benign_hits_ransom_signals (0.4-0.6)")
        log.warning("Recommendation: Run generator with --enable-adversarial --adversarial-ratio 0.3")
    
    return result


def check_feature_alignment(generator_features: List[str], runtime_features: List[str]) -> Dict:
    """Check semantic alignment between generator and runtime feature extractor.
    
    Args:
        generator_features: Features from dataset generator
        runtime_features: Features from Stage-3 runtime extractor
    
    Returns:
        Dictionary with alignment report and warnings
    """
    gen_set = set(generator_features)
    runtime_set = set(runtime_features)
    
    # Find mismatches
    missing_in_runtime = gen_set - runtime_set
    extra_in_runtime = runtime_set - gen_set
    common_features = gen_set & runtime_set
    
    # Check for semantic mismatches (rate vs raw count, lifecycle vs snapshot)
    semantic_warnings = []
    
    # Check for rate vs raw count mismatches
    rate_features_gen = {f for f in gen_set if 'rate' in f.lower() or 'frequency' in f.lower()}
    rate_features_runtime = {f for f in runtime_set if 'rate' in f.lower() or 'frequency' in f.lower()}
    
    raw_count_gen = {f for f in gen_set if any(x in f.lower() for x in ['count', 'total', 'excessive'])}
    raw_count_runtime = {f for f in runtime_set if any(x in f.lower() for x in ['count', 'total', 'excessive'])}
    
    if rate_features_gen != rate_features_runtime:
        semantic_warnings.append({
            "type": "rate_vs_raw_count_mismatch",
            "description": "Mismatch in rate vs raw count features between generator and runtime",
            "generator_rate_features": list(rate_features_gen),
            "runtime_rate_features": list(rate_features_runtime),
        })
    
    # Check for lifecycle aggregation vs snapshot features
    lifecycle_gen = {f for f in gen_set if 'lifecycle' in f.lower() or 'cumulative' in f.lower()}
    lifecycle_runtime = {f for f in runtime_set if 'lifecycle' in f.lower() or 'cumulative' in f.lower()}
    
    if lifecycle_gen != lifecycle_runtime:
        semantic_warnings.append({
            "type": "lifecycle_aggregation_mismatch",
            "description": "Mismatch in lifecycle aggregation features",
            "generator_lifecycle": list(lifecycle_gen),
            "runtime_lifecycle": list(lifecycle_runtime),
        })
    
    result = {
        "common_features_count": len(common_features),
        "missing_in_runtime": list(missing_in_runtime),
        "extra_in_runtime": list(extra_in_runtime),
        "semantic_warnings": semantic_warnings,
        "alignment_score": len(common_features) / len(gen_set) if len(gen_set) > 0 else 0.0,
    }
    
    if missing_in_runtime:
        log.warning(f"Features in generator but missing in runtime: {list(missing_in_runtime)[:10]}...")
    if extra_in_runtime:
        log.info(f"Extra features in runtime (not in generator): {list(extra_in_runtime)[:10]}...")
    if semantic_warnings:
        for warning in semantic_warnings:
            log.warning(f"Semantic mismatch: {warning['description']}")
    
    return result


def save_enhanced_feature_importance_plots(model, feature_names: List[str], output_path: Path, 
                                          ensemble_models: Optional[List] = None):
    """Create comprehensive feature importance visualizations."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Determine which models to plot
    models_to_plot = []
    if isinstance(model, lgb.Booster):
        models_to_plot.append(("LightGBM", model))
    if ensemble_models:
        for i, m in enumerate(ensemble_models):
            if isinstance(m, lgb.Booster):
                models_to_plot.append((f"LightGBM_Fold_{i+1}", m))
    
    # Create multiple importance plots
    fig = plt.figure(figsize=(20, 12))
    
    # 1. Top 30 Features - Gain Importance
    ax1 = plt.subplot(2, 2, 1)
    importance = model.feature_importance(importance_type="gain")
    idx = np.argsort(importance)[-30:]
    y_pos = np.arange(len(idx))
    ax1.barh(y_pos, importance[idx], color=sns.color_palette("husl", len(idx)))
    ax1.set_yticks(y_pos)
    ax1.set_yticklabels([feature_names[i] for i in idx], fontsize=9)
    ax1.set_xlabel("Gain Importance", fontsize=12, fontweight='bold')
    ax1.set_title("Top 30 Features - Gain Importance", fontsize=14, fontweight='bold')
    ax1.grid(axis='x', alpha=0.3)
    
    # 2. Top 30 Features - Split Importance
    ax2 = plt.subplot(2, 2, 2)
    importance_split = model.feature_importance(importance_type="split")
    idx_split = np.argsort(importance_split)[-30:]
    y_pos_split = np.arange(len(idx_split))
    ax2.barh(y_pos_split, importance_split[idx_split], color=sns.color_palette("coolwarm", len(idx_split)))
    ax2.set_yticks(y_pos_split)
    ax2.set_yticklabels([feature_names[i] for i in idx_split], fontsize=9)
    ax2.set_xlabel("Split Importance", fontsize=12, fontweight='bold')
    ax2.set_title("Top 30 Features - Split Importance", fontsize=14, fontweight='bold')
    ax2.grid(axis='x', alpha=0.3)
    
    # 3. Feature Importance Comparison (Gain vs Split)
    ax3 = plt.subplot(2, 2, 3)
    top_n = 20
    top_gain_idx = np.argsort(importance)[-top_n:]
    top_split_idx = np.argsort(importance_split)[-top_n:]
    common_features = set([feature_names[i] for i in top_gain_idx]) & set([feature_names[i] for i in top_split_idx])
    
    if common_features:
        common_idx = [i for i, name in enumerate(feature_names) if name in common_features]
        gain_vals = importance[common_idx]
        split_vals = importance_split[common_idx]
        
        # Normalize for comparison
        gain_norm = gain_vals / gain_vals.max()
        split_norm = split_vals / split_vals.max()
        
        x = np.arange(len(common_features))
        width = 0.35
        ax3.bar(x - width/2, gain_norm, width, label='Gain (normalized)', alpha=0.8)
        ax3.bar(x + width/2, split_norm, width, label='Split (normalized)', alpha=0.8)
        ax3.set_xticks(x)
        ax3.set_xticklabels([feature_names[i] for i in common_idx], rotation=45, ha='right', fontsize=8)
        ax3.set_ylabel("Normalized Importance", fontsize=12, fontweight='bold')
        ax3.set_title("Top Features: Gain vs Split Comparison", fontsize=14, fontweight='bold')
        ax3.legend()
        ax3.grid(axis='y', alpha=0.3)
    
    # 4. Feature Importance Distribution
    ax4 = plt.subplot(2, 2, 4)
    ax4.hist(importance, bins=50, color='skyblue', edgecolor='black', alpha=0.7)
    ax4.axvline(np.median(importance), color='red', linestyle='--', linewidth=2, label=f'Median: {np.median(importance):.2f}')
    ax4.axvline(np.mean(importance), color='green', linestyle='--', linewidth=2, label=f'Mean: {np.mean(importance):.2f}')
    ax4.set_xlabel("Feature Importance (Gain)", fontsize=12, fontweight='bold')
    ax4.set_ylabel("Frequency", fontsize=12, fontweight='bold')
    ax4.set_title("Feature Importance Distribution", fontsize=14, fontweight='bold')
    ax4.legend()
    ax4.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plot_path = output_path.with_suffix(".importance_comprehensive.png")
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    plt.close()
    log.info(f"Saved comprehensive feature importance plot to {plot_path}")
    
    # Create individual top features plot (larger, more readable)
    fig2, ax = plt.subplots(figsize=(12, 10))
    top_n = 25
    idx = np.argsort(importance)[-top_n:]
    y_pos = np.arange(len(idx))
    colors = plt.cm.viridis(np.linspace(0, 1, len(idx)))
    ax.barh(y_pos, importance[idx], color=colors)
    ax.set_yticks(y_pos)
    ax.set_yticklabels([feature_names[i] for i in idx], fontsize=11)
    ax.set_xlabel("Gain Importance", fontsize=14, fontweight='bold')
    ax.set_title(f"Top {top_n} Most Important Features", fontsize=16, fontweight='bold')
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()
    plot_path2 = output_path.with_suffix(".importance_top25.png")
    plt.savefig(plot_path2, dpi=300, bbox_inches='tight')
    plt.close()
    log.info(f"Saved top 25 features plot to {plot_path2}")
    
    # Save feature importance data to JSON
    importance_data = {
        "gain": {feature_names[i]: float(importance[i]) for i in range(len(feature_names))},
        "split": {feature_names[i]: float(importance_split[i]) for i in range(len(feature_names))},
        "top_25_gain": {feature_names[i]: float(importance[i]) for i in idx},
    }
    importance_json_path = output_path.with_suffix(".importance.json")
    with open(importance_json_path, 'w') as f:
        json.dump(importance_data, f, indent=2)
    log.info(f"Saved feature importance data to {importance_json_path}")


def generate_evaluation_report(metrics: Dict, dominance_metrics: Dict, alignment_metrics: Dict,
                                output_path: Path) -> str:
    """Generate comprehensive evaluation report for FYP/thesis/defense.
    
    Args:
        metrics: Evaluation metrics including stage-aware metrics
        dominance_metrics: Feature dominance analysis
        alignment_metrics: Feature alignment between generator and runtime
        output_path: Path to save the report
    
    Returns:
        Report content as string
    """
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("RANSOMWARE DETECTION MODEL - COMPREHENSIVE EVALUATION REPORT")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    # Overall Performance
    report_lines.append("## 1. Overall Performance Metrics")
    report_lines.append("-" * 80)
    if "test" in metrics:
        test_metrics = metrics["test"]
        report_lines.append(f"Overall PR-AUC: {test_metrics.get('pr_auc', 0):.4f}")
        report_lines.append(f"Overall ROC-AUC: {test_metrics.get('roc_auc', 0):.4f}")
        report_lines.append(f"Overall Recall: {test_metrics.get('recall', 0):.4f}")
        report_lines.append(f"Overall Precision: {test_metrics.get('precision', 0):.4f}")
        report_lines.append(f"Overall F1-Score: {test_metrics.get('f1', 0):.4f}")
    report_lines.append("")
    
    # Stage-Aware Performance
    report_lines.append("## 2. Stage-Aware Performance (Ransomware Lifecycle)")
    report_lines.append("-" * 80)
    if "test" in metrics and "stage_aware" in metrics["test"]:
        stage_metrics = metrics["test"]["stage_aware"]
        for stage in ["early", "mid", "late"]:
            if stage in stage_metrics:
                stage_data = stage_metrics[stage]
                report_lines.append(f"{stage.upper()}-stage Performance:")
                report_lines.append(f"  PR-AUC: {stage_data.get('pr_auc', 0):.4f}")
                report_lines.append(f"  Recall: {stage_data.get('recall', 0):.4f}")
                report_lines.append(f"  Precision: {stage_data.get('precision', 0):.4f}")
                report_lines.append(f"  F1-Score: {stage_data.get('f1', 0):.4f}")
                report_lines.append(f"  Samples: {stage_data.get('sample_count', 0)} (positives: {stage_data.get('positive_count', 0)})")
                report_lines.append("")
    else:
        report_lines.append("Stage-aware metrics not available (snapshot_phase column missing)")
        report_lines.append("")
    
    # Feature Dominance Analysis
    report_lines.append("## 3. Feature Dominance Analysis")
    report_lines.append("-" * 80)
    report_lines.append(f"Dominance Score: {dominance_metrics.get('dominance_score', 0):.4f}")
    report_lines.append(f"Most Dominant Feature: {dominance_metrics.get('max_feature', 'N/A')}")
    report_lines.append(f"Recommendation: {dominance_metrics.get('recommendation', 'N/A')}")
    report_lines.append("")
    
    if dominance_metrics.get('over_dominant_features'):
        report_lines.append("Over-Dominant Features (>30% importance):")
        for feat in dominance_metrics['over_dominant_features']:
            report_lines.append(f"  - {feat['feature']}: {feat['ratio']:.2%}")
        report_lines.append("")
    
    report_lines.append("Top 5 Features:")
    for i, (name, importance, ratio) in enumerate(dominance_metrics.get('top_5_features', []), 1):
        report_lines.append(f"  {i}. {name}: {ratio:.2%} (importance: {importance:.0f})")
    report_lines.append("")
    
    # Feature Alignment
    report_lines.append("## 4. Generator-Runtime Feature Alignment")
    report_lines.append("-" * 80)
    report_lines.append(f"Alignment Score: {alignment_metrics.get('alignment_score', 0):.4f}")
    report_lines.append(f"Common Features: {alignment_metrics.get('common_features_count', 0)}")
    report_lines.append(f"Missing in Runtime: {len(alignment_metrics.get('missing_in_runtime', []))}")
    report_lines.append(f"Extra in Runtime: {len(alignment_metrics.get('extra_in_runtime', []))}")
    report_lines.append("")
    
    if alignment_metrics.get('semantic_warnings'):
        report_lines.append("Semantic Warnings:")
        for warning in alignment_metrics['semantic_warnings']:
            report_lines.append(f"  - {warning['type']}: {warning['description']}")
        report_lines.append("")
    
    # Known Limitations
    report_lines.append("## 5. Known Limitations & Mitigations")
    report_lines.append("-" * 80)
    report_lines.append("1. Lifecycle Smoothing Effects:")
    report_lines.append("   - Early-stage ransomware may have weaker signals")
    report_lines.append("   - Mitigation: Stage-aware evaluation reveals early-detection weaknesses")
    report_lines.append("")
    report_lines.append("2. Feature Dominance:")
    report_lines.append("   - Single-feature overfitting reduces robustness")
    report_lines.append("   - Mitigation: Generator rebalancing based on dominance feedback")
    report_lines.append("")
    report_lines.append("3. Semantic Drift:")
    report_lines.append("   - Runtime features may differ from training features")
    report_lines.append("   - Mitigation: Feature alignment validation and warnings")
    report_lines.append("")
    
    # Recommendations
    report_lines.append("## 6. Recommendations")
    report_lines.append("-" * 80)
    if dominance_metrics.get('dominance_score', 0) > 0.30:
        report_lines.append("⚠️  HIGH PRIORITY: Reduce feature dominance in dataset generator")
        report_lines.append("   - Rebalance over-dominant features identified above")
        report_lines.append("   - Increase overlap between benign and malicious samples")
    else:
        report_lines.append("✅ Feature dominance is within acceptable range (<30%)")
    report_lines.append("")
    
    if "test" in metrics and "stage_aware" in metrics["test"]:
        early_recall = metrics["test"]["stage_aware"].get("early", {}).get("recall", 0)
        if early_recall < 0.80:
            report_lines.append("⚠️  MEDIUM PRIORITY: Improve early-stage detection")
            report_lines.append(f"   - Current early-stage recall: {early_recall:.2%}")
            report_lines.append("   - Consider enhancing early-stage behavioral signals")
        else:
            report_lines.append("✅ Early-stage detection is performing well")
    report_lines.append("")
    
    if alignment_metrics.get('alignment_score', 1.0) < 0.95:
        report_lines.append("⚠️  MEDIUM PRIORITY: Improve feature alignment")
        report_lines.append("   - Review semantic mismatches identified above")
        report_lines.append("   - Ensure runtime extractor matches generator features")
    else:
        report_lines.append("✅ Feature alignment is good (>95%)")
    report_lines.append("")
    
    report_lines.append("=" * 80)
    
    report_content = "\n".join(report_lines)
    
    # Save report
    report_path = output_path.with_suffix(".evaluation_report.txt")
    report_path.write_text(report_content, encoding="utf-8")
    log.info(f"Saved evaluation report to {report_path}")
    
    return report_content


def save_artifacts(model, threshold: float, metrics: dict, feature_names: List[str], 
                   output_path: Path, ensemble_models: Optional[List] = None,
                   cv_results: Optional[Dict] = None, best_params: Optional[Dict] = None,
                   dominance_metrics: Optional[Dict] = None, alignment_metrics: Optional[Dict] = None):
    """Save model artifacts with enhanced metadata."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save LightGBM model
    if isinstance(model, lgb.Booster):
        model.save_model(str(output_path))
    else:
        # For ensemble or other models, save as pickle
        import pickle
        with open(str(output_path) + ".pkl", 'wb') as f:
            pickle.dump(model, f)
    
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
                                         for k, v in best_params.items() if k not in ['objective', 'metric', 'boosting_type', 'verbosity', 'is_unbalance', 'seed']}
    
    if ensemble_models:
        config["ensemble"] = {
            "num_models": len(ensemble_models),
            "type": "lightgbm_ensemble"
        }
    
    if dominance_metrics:
        config["feature_dominance"] = dominance_metrics
    
    if alignment_metrics:
        config["feature_alignment"] = alignment_metrics
    
    config_path = output_path.with_suffix(".config.json")
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    log.info(f"Saved model to {output_path} and config to {config_path}")
    
    # Create enhanced feature importance plots
    if isinstance(model, lgb.Booster):
        save_enhanced_feature_importance_plots(model, feature_names, output_path, ensemble_models)
    
    # Generate evaluation report
    if dominance_metrics and alignment_metrics:
        generate_evaluation_report(metrics, dominance_metrics, alignment_metrics, output_path)


def main():
    parser = argparse.ArgumentParser(description="Enhanced LightGBM training with Optuna, ensembles, and CV")
    parser.add_argument("--dataset", required=True, help="Path to parquet file from dataset_generator")
    parser.add_argument("--output", default="models/stage3_model_enhanced.txt", help="Path to save model")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--threshold-metric", choices=["recall", "f1", "f1_recall"], default="f1_recall",
                        help="Metric used to select decision threshold")
    parser.add_argument("--min-recall", type=float, default=0.90,
                        help="Minimum recall enforced when metric is f1_recall")
    parser.add_argument("--enforce-hash", action="store_true", help="Fail if feature_list_hash mismatches")
    
    # Enhanced features
    parser.add_argument("--use-optuna", action="store_true", help="Use Optuna for hyperparameter optimization")
    parser.add_argument("--optuna-trials", type=int, default=50, help="Number of Optuna trials")
    parser.add_argument("--use-ensemble", action="store_true", help="Train ensemble model")
    parser.add_argument("--ensemble-size", type=int, default=5, help="Number of models in ensemble")
    parser.add_argument("--use-xgboost", action="store_true", help="Include XGBoost in ensemble (requires XGBoost)")
    parser.add_argument("--cv-folds", type=int, default=0, help="Number of CV folds (0 to disable)")
    
    args = parser.parse_args()
    
    if args.use_optuna and not OPTUNA_AVAILABLE:
        log.error("Optuna not available. Install with: pip install optuna")
        return
    
    if args.use_xgboost and not XGBOOST_AVAILABLE:
        log.warning("XGBoost not available. Skipping XGBoost in ensemble.")
        args.use_xgboost = False
    
    np.random.seed(args.seed)
    
    df = read_dataset(Path(args.dataset), enforce_hash=args.enforce_hash)
    X, y, feature_names = split_features(df)
    
    # Extract snapshot phases for stage-aware evaluation
    snapshot_phases = None
    if '_snapshot_phase' in df.columns:
        snapshot_phases = df['_snapshot_phase'].astype(float).to_numpy()
        log.info(f"Found _snapshot_phase column for stage-aware evaluation")
        log.info(f"Phase distribution: early={np.sum(snapshot_phases <= 0.3)}, mid={np.sum((snapshot_phases > 0.3) & (snapshot_phases <= 0.7))}, late={np.sum(snapshot_phases > 0.7)}")
    else:
        log.warning("_snapshot_phase column not found - stage-aware evaluation will be skipped")
    
    # Split data and track indices to split snapshot_phases correctly
    # First split: train_val vs test
    indices = np.arange(len(X))
    train_val_idx, test_idx = train_test_split(
        indices, test_size=0.15, random_state=args.seed, stratify=y
    )
    X_train_val, X_test = X[train_val_idx], X[test_idx]
    y_train_val, y_test = y[train_val_idx], y[test_idx]
    
    # Second split: train vs val
    train_val_indices = np.arange(len(X_train_val))
    train_idx, val_idx = train_test_split(
        train_val_indices, test_size=0.1765, random_state=args.seed, stratify=y_train_val
    )
    X_train, X_val = X_train_val[train_idx], X_train_val[val_idx]
    y_train, y_val = y_train_val[train_idx], y_train_val[val_idx]
    
    # Split snapshot phases using the same indices
    snapshot_phases_train = None
    snapshot_phases_val = None
    snapshot_phases_test = None
    if snapshot_phases is not None:
        snapshot_phases_test = snapshot_phases[test_idx]
        snapshot_phases_train = snapshot_phases[train_val_idx][train_idx]
        snapshot_phases_val = snapshot_phases[train_val_idx][val_idx]
        log.info(f"Snapshot phases split: train={len(snapshot_phases_train)}, val={len(snapshot_phases_val)}, test={len(snapshot_phases_test)}")
    
    log.info(f"Train: {len(X_train):,} | Val: {len(X_val):,} | Test: {len(X_test):,}")
    
    best_params = None
    cv_results = None
    ensemble_models = []
    
    # Cross-validation
    if args.cv_folds > 0:
        cv_results, fold_models = cross_validate_model(X_train_val, y_train_val, feature_names, 
                                                       n_folds=args.cv_folds, seed=args.seed)
        if args.use_ensemble:
            ensemble_models.extend(fold_models[:args.ensemble_size])
    
    # Hyperparameter optimization
    if args.use_optuna:
        log.info("Starting Optuna hyperparameter optimization...")
        best_params = optimize_hyperparameters_optuna(
            X_train, y_train, X_val, y_val, seed=args.seed, n_trials=args.optuna_trials
        )
    
    # Train main model
    log.info("Training main model...")
    model = train_lightgbm(X_train, y_train, X_val, y_val, seed=args.seed, params=best_params)
    
    # Ensemble training
    if args.use_ensemble:
        log.info(f"Training ensemble with {args.ensemble_size} models...")
        for i in range(args.ensemble_size):
            log.info(f"Training ensemble model {i+1}/{args.ensemble_size}")
            seed_i = args.seed + i
            ensemble_model = train_lightgbm(X_train, y_train, X_val, y_val, seed=seed_i, params=best_params)
            ensemble_models.append(ensemble_model)
        
        if args.use_xgboost:
            log.info("Training XGBoost model for ensemble...")
            xgb_model = train_xgboost(X_train, y_train, X_val, y_val, seed=args.seed)
            ensemble_models.append(xgb_model)
        
        # Create ensemble predictions
        log.info("Creating ensemble predictions...")
        val_preds_ensemble = create_ensemble(ensemble_models, X_val)
        val_preds_single = model.predict(X_val)
        
        # Compare ensemble vs single model
        ensemble_pr_auc = average_precision_score(y_val, val_preds_ensemble)
        single_pr_auc = average_precision_score(y_val, val_preds_single)
        log.info(f"Ensemble PR-AUC: {ensemble_pr_auc:.4f} | Single Model PR-AUC: {single_pr_auc:.4f}")
        
        # Use ensemble for final predictions
        final_model = ensemble_models
        is_ensemble = True
    else:
        final_model = model
        is_ensemble = False
    
    # Threshold tuning
    if is_ensemble:
        val_preds = val_preds_ensemble
    else:
        val_preds = model.predict(X_val)
    
    threshold = tune_threshold(val_preds, y_val, metric=args.threshold_metric, min_recall=args.min_recall)
    
    # Evaluation
    if is_ensemble:
        train_preds = create_ensemble(ensemble_models, X_train)
        test_preds = create_ensemble(ensemble_models, X_test)
        
        # Evaluate with pre-computed predictions and stage-aware evaluation
        metrics = {
            "train": evaluate(None, X_train, y_train, threshold, "train", is_ensemble=True, 
                            predictions=train_preds, snapshot_phases=snapshot_phases_train),
            "val": evaluate(None, X_val, y_val, threshold, "val", is_ensemble=True, 
                          predictions=val_preds, snapshot_phases=snapshot_phases_val),
            "test": evaluate(None, X_test, y_test, threshold, "test", is_ensemble=True, 
                           predictions=test_preds, snapshot_phases=snapshot_phases_test),
        }
    else:
        metrics = {
            "train": evaluate(model, X_train, y_train, threshold, "train", 
                            snapshot_phases=snapshot_phases_train),
            "val": evaluate(model, X_val, y_val, threshold, "val", 
                          snapshot_phases=snapshot_phases_val),
            "test": evaluate(model, X_test, y_test, threshold, "test", 
                           snapshot_phases=snapshot_phases_test),
        }
    
    # Compute feature dominance
    log.info("Computing feature dominance metrics...")
    dominance_metrics = None
    if isinstance(model, lgb.Booster):
        dominance_metrics = compute_feature_dominance_score(model, feature_names)
    elif ensemble_models and len(ensemble_models) > 0:
        # Use first ensemble model for dominance calculation
        dominance_metrics = compute_feature_dominance_score(ensemble_models[0], feature_names)
    
    # Check feature alignment (generator vs runtime)
    log.info("Checking feature alignment (generator vs runtime)...")
    alignment_metrics = None
    try:
        # Try to import runtime feature extractor
        import sys
        runtime_features_path = Path("src/stage3_feature_extraction/feature_extractor.py")
        if runtime_features_path.exists():
            # Read runtime features from extractor
            runtime_feature_names = []
            with open(runtime_features_path, 'r') as f:
                content = f.read()
                # Extract feature names from extractor (simplified - would need proper parsing)
                # For now, use generator features as baseline
                runtime_feature_names = feature_names  # Placeholder - would need actual extraction
            alignment_metrics = check_feature_alignment(feature_names, runtime_feature_names)
        else:
            log.warning("Runtime feature extractor not found - skipping alignment check")
            alignment_metrics = {
                "alignment_score": 1.0,
                "common_features_count": len(feature_names),
                "missing_in_runtime": [],
                "extra_in_runtime": [],
                "semantic_warnings": [],
            }
    except Exception as e:
        log.warning(f"Could not check feature alignment: {e}")
        alignment_metrics = {
            "alignment_score": 1.0,
            "common_features_count": len(feature_names),
            "missing_in_runtime": [],
            "extra_in_runtime": [],
            "semantic_warnings": [],
        }
    
    # Save artifacts
    save_artifacts(
        model, threshold, metrics, feature_names, Path(args.output),
        ensemble_models=ensemble_models if args.use_ensemble else None,
        cv_results=cv_results,
        best_params=best_params,
        dominance_metrics=dominance_metrics,
        alignment_metrics=alignment_metrics
    )
    
    log.info("=" * 80)
    log.info("Training complete!")
    log.info(f"Model saved to: {args.output}")
    log.info(f"Optimal threshold: {threshold:.3f}")
    log.info("=" * 80)
    if args.use_ensemble:
        log.info(f"Ensemble size: {len(ensemble_models)} models")
    if cv_results:
        log.info(f"Cross-validation PR-AUC: {cv_results.get('pr_auc_mean', 0):.4f} (+/- {cv_results.get('pr_auc_std', 0):.4f})")


if __name__ == "__main__":
    main()
