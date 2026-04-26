"""
Stage 4 ML Model Training

Trains a LightGBM binary classifier (malicious vs. benign) on Stage 4 dataset.

Usage:
    python train_stage4_model.py \
        --data data/stage4/stage4_train.parquet \
        --output models/stage4_v1 \
        --train-ratio 0.6 \
        --val-ratio 0.2

Output:
    models/stage4_v1.txt (LightGBM model)
    models/stage4_v1.config.json (hyperparameters + feature names)
    models/stage4_v1.importance.json (feature importance)
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Tuple, List, Dict, Any
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    average_precision_score,
    roc_curve,
    roc_auc_score,
    precision_recall_curve,
    f1_score,
    precision_score,
    recall_score,
)
import numpy as np

try:
    import lightgbm as lgb
    import pyarrow.parquet as pq
except ImportError:
    raise RuntimeError("Install dependencies: pip install lightgbm scikit-learn pyarrow")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("stage4_trainer")


class Stage4ModelTrainer:
    """Train Stage 4 LightGBM model"""

    EXCLUDED_COLUMNS = {
        "sample_id", "image", "host", "yara_context",
        "process_guid", "attack_scenario_id", "label_source", "split",
        "attack_stage", "mitre_techniques", "evasion_type", "label_name",
        "label",
    }
    
    def __init__(
        self,
        data_path: str,
        output_dir: str,
        train_ratio: float = 0.6,
        val_ratio: float = 0.2,
        random_state: int = 42,
    ):
        self.data_path = Path(data_path)
        self.output_dir = Path(output_dir)
        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = 1.0 - train_ratio - val_ratio
        self.random_state = random_state
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.feature_names = []
        self.feature_importance = {}
        self.evaluation_summary = {}
    
    def load_data(self) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Load Stage 4 parquet dataset"""
        logger.info(f"Loading data from {self.data_path}")
        
        table = pq.read_table(self.data_path)
        df_dict = table.to_pydict()
        columns = list(df_dict.keys())
        feature_names = []

        for name in columns:
            if name in self.EXCLUDED_COLUMNS:
                continue
            values = df_dict.get(name, [])
            first_non_null = next((value for value in values if value is not None), None)
            if isinstance(first_non_null, (int, float, bool, np.integer, np.floating)):
                feature_names.append(name)
        
        # Extract features and labels
        X_list = []
        y_list = []
        
        n_rows = len(df_dict.get("label", []))
        logger.info(f"Total samples in dataset: {n_rows}")
        logger.info(f"Using {len(feature_names)} numeric features")
        
        for i in range(n_rows):
            label = df_dict.get("label", [None])[i]
            
            # Skip unknown labels (-1)
            if label == -1:
                continue
            
            # Extract feature values
            row = []
            for fname in feature_names:
                values = df_dict.get(fname, [])
                if isinstance(values, list) and len(values) > i:
                    value = values[i]
                    if isinstance(value, bool):
                        value = int(value)
                    if value is None:
                        value = 0.0
                    row.append(float(value))
                else:
                    row.append(0.0)
            
            X_list.append(row)
            y_list.append(int(label))
        
        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)
        
        logger.info(f"Loaded {X.shape[0]} samples with {X.shape[1]} features")
        logger.info(f"Label distribution: {np.bincount(y)}")
        
        return X, y, feature_names
    
    def train(self, X: np.ndarray, y: np.ndarray) -> None:
        """Train LightGBM model"""
        logger.info("=" * 80)
        logger.info("Training Stage 4 Model")
        logger.info("=" * 80)
        
        # Split data
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=self.test_ratio, random_state=self.random_state, stratify=y
        )
        val_ratio_adjusted = self.val_ratio / (self.train_ratio + self.val_ratio)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio_adjusted, random_state=self.random_state, stratify=y_temp
        )
        
        logger.info(f"Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")
        logger.info(f"Train label dist: {np.bincount(y_train)}")
        logger.info(f"Val label dist: {np.bincount(y_val)}")
        logger.info(f"Test label dist: {np.bincount(y_test)}")
        
        # Compute class weights
        pos_count = np.sum(y_train == 1)
        neg_count = np.sum(y_train == 0)
        scale_pos_weight = neg_count / max(pos_count, 1)
        logger.info(f"Scale pos weight: {scale_pos_weight:.2f}")
        
        # Training data for LightGBM
        train_data = lgb.Dataset(X_train, label=y_train)
        val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
        
        # Hyperparameters (optimized for precision, not recall like Stage 3)
        params = {
            "objective": "binary",
            "metric": "auc",
            "scale_pos_weight": scale_pos_weight,
            "learning_rate": 0.05,
            "num_leaves": 31,
            "max_depth": 7,
            "min_child_samples": 20,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "verbose": -1,
        }
        
        logger.info(f"Hyperparameters: {json.dumps(params, indent=2)}")
        
        # Train
        self.model = lgb.train(
            params,
            train_data,
            num_boost_round=300,
            valid_sets=[train_data, val_data],
            valid_names=["train", "val"],
            callbacks=[
                lgb.early_stopping(50, verbose=True),
                lgb.log_evaluation(period=50),
            ],
        )
        
        logger.info("✓ Model trained successfully")
        
        # Evaluate
        self._evaluate(X_train, y_train, X_val, y_val, X_test, y_test)
    
    def _evaluate(self, X_train, y_train, X_val, y_val, X_test, y_test) -> None:
        """Evaluate model on all splits"""
        logger.info("=" * 80)
        logger.info("Model Evaluation")
        logger.info("=" * 80)

        split_metrics = {}
        split_curves = {}
        
        for split_name, X_split, y_split in [("Train", X_train, y_train), ("Val", X_val, y_val), ("Test", X_test, y_test)]:
            y_proba = self.model.predict(X_split)
            y_pred = (y_proba >= 0.5).astype(int)
            
            auc = roc_auc_score(y_split, y_proba)
            pr_auc = average_precision_score(y_split, y_proba)
            precision = precision_score(y_split, y_pred)
            recall = recall_score(y_split, y_pred)
            f1 = f1_score(y_split, y_pred)
            fpr, tpr, roc_thresholds = roc_curve(y_split, y_proba)
            pr_precision, pr_recall, pr_thresholds = precision_recall_curve(y_split, y_proba)

            split_key = split_name.lower()
            split_metrics[split_key] = {
                "auc": float(auc),
                "pr_auc": float(pr_auc),
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
                "threshold": 0.5,
                "confusion_matrix": confusion_matrix(y_split, y_pred).tolist(),
                "classification_report": classification_report(
                    y_split,
                    y_pred,
                    target_names=["benign", "malicious"],
                    output_dict=True,
                    zero_division=0,
                ),
            }
            split_curves[split_key] = {
                "roc": {
                    "fpr": fpr.tolist(),
                    "tpr": tpr.tolist(),
                    "thresholds": roc_thresholds.tolist(),
                },
                "pr": {
                    "precision": pr_precision.tolist(),
                    "recall": pr_recall.tolist(),
                    "thresholds": pr_thresholds.tolist(),
                },
            }
            
            logger.info(f"\n{split_name} Metrics:")
            logger.info(f"  AUC: {auc:.4f}")
            logger.info(f"  PR-AUC: {pr_auc:.4f}")
            logger.info(f"  Precision: {precision:.4f}")
            logger.info(f"  Recall: {recall:.4f}")
            logger.info(f"  F1: {f1:.4f}")
            
            logger.info(f"\n{split_name} Classification Report:")
            logger.info("\n" + classification_report(y_split, y_pred, target_names=["benign", "malicious"]))
        
        # Feature importance
        self.feature_importance = self.model.feature_importance(importance_type="gain")
        top_features = sorted(
            zip(self.feature_names, self.feature_importance),
            key=lambda x: x[1],
            reverse=True
        )[:20]
        
        logger.info("\nTop 20 Important Features:")
        for fname, importance in top_features:
            logger.info(f"  {fname}: {importance:.2f}")

        best_threshold, best_threshold_metrics = self._find_best_threshold(X_val, y_val)
        logger.info("\nValidation threshold sweep:")
        logger.info(
            "  Best threshold by F1: %.4f (precision=%.4f recall=%.4f f1=%.4f)",
            best_threshold,
            best_threshold_metrics["precision"],
            best_threshold_metrics["recall"],
            best_threshold_metrics["f1"],
        )

        self.evaluation_summary = {
            "threshold_recommendation": {
                "current": 0.5,
                "recommended": float(best_threshold),
                "reason": "Validation threshold maximizing F1",
                "metrics": best_threshold_metrics,
            },
            "splits": split_metrics,
            "curves": split_curves,
            "feature_count": len(self.feature_names),
            "top_features": [{"feature": fname, "importance": float(importance)} for fname, importance in top_features],
        }

        self._save_evaluation_report()

    def _find_best_threshold(self, X_val: np.ndarray, y_val: np.ndarray) -> Tuple[float, Dict[str, float]]:
        """Find the validation threshold with the best F1 score."""
        y_proba = self.model.predict(X_val)
        thresholds = np.unique(np.concatenate(([0.0, 0.5, 1.0], y_proba)))

        best_threshold = 0.5
        best_metrics = {"precision": 0.0, "recall": 0.0, "f1": 0.0}
        best_f1 = -1.0

        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)
            precision = precision_score(y_val, y_pred, zero_division=0)
            recall = recall_score(y_val, y_pred, zero_division=0)
            f1 = f1_score(y_val, y_pred, zero_division=0)

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = float(threshold)
                best_metrics = {
                    "precision": float(precision),
                    "recall": float(recall),
                    "f1": float(f1),
                }

        return best_threshold, best_metrics

    def _save_evaluation_report(self) -> None:
        """Persist evaluation summary as JSON and text report."""
        if not self.evaluation_summary:
            return

        report_path = self.output_dir / f"{self.output_dir.name}.evaluation_report.txt"
        metrics_path = self.output_dir / f"{self.output_dir.name}.metrics.json"

        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(self.evaluation_summary, f, indent=2, sort_keys=True)
        logger.info(f"✓ Evaluation metrics saved to {metrics_path}")

        report_lines = [
            "Stage 4 Model Evaluation Report",
            "=" * 80,
            f"Model: {self.output_dir.name}",
            f"Features: {len(self.feature_names)}",
            f"Threshold (current): {self.evaluation_summary['threshold_recommendation']['current']:.4f}",
            f"Threshold (recommended): {self.evaluation_summary['threshold_recommendation']['recommended']:.4f}",
            f"Threshold note: {self.evaluation_summary['threshold_recommendation']['reason']}",
            "",
        ]

        for split_name in ("train", "val", "test"):
            split_data = self.evaluation_summary["splits"].get(split_name, {})
            report_lines.extend([
                f"[{split_name.upper()}]",
                f"  ROC-AUC: {split_data.get('auc', 0.0):.4f}",
                f"  PR-AUC: {split_data.get('pr_auc', 0.0):.4f}",
                f"  Precision: {split_data.get('precision', 0.0):.4f}",
                f"  Recall: {split_data.get('recall', 0.0):.4f}",
                f"  F1: {split_data.get('f1', 0.0):.4f}",
                f"  Confusion Matrix: {split_data.get('confusion_matrix', [])}",
                "",
            ])

        report_lines.append("Top Features:")
        for item in self.evaluation_summary.get("top_features", [])[:20]:
            report_lines.append(f"  {item['feature']}: {item['importance']:.2f}")

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines).rstrip() + "\n")
        logger.info(f"✓ Evaluation report saved to {report_path}")
    
    def save_model(self) -> None:
        """Save model and metadata"""
        if self.model is None:
            raise RuntimeError("Model not trained yet")
        
        # Save model
        model_path = self.output_dir / f"{self.output_dir.name}.txt"
        self.model.save_model(str(model_path))
        logger.info(f"✓ Model saved to {model_path}")
        
        # Save config
        config = {
            "model_name": "stage4_v1",
            "model_type": "lightgbm",
            "num_features": len(self.feature_names),
            "feature_names": self.feature_names,
            "num_rounds": self.model.num_trees(),
            "objective": "binary",
            "threshold": 0.5,
        }
        config_path = self.output_dir / f"{self.output_dir.name}.config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"✓ Config saved to {config_path}")
        
        # Save feature importance
        importance_dict = {
            fname: float(imp) for fname, imp in zip(self.feature_names, self.feature_importance)
        }
        importance_path = self.output_dir / f"{self.output_dir.name}.importance.json"
        with open(importance_path, "w") as f:
            json.dump(importance_dict, f, indent=2, sort_keys=True)
        logger.info(f"✓ Feature importance saved to {importance_path}")


def main():
    parser = argparse.ArgumentParser(description="Train Stage 4 LightGBM model")
    parser.add_argument("--data", type=str, required=True, help="Path to Stage 4 parquet dataset")
    parser.add_argument("--output", type=str, default="models/stage4_v1", help="Output model path (without extension)")
    parser.add_argument("--train-ratio", type=float, default=0.6, help="Training set ratio")
    parser.add_argument("--val-ratio", type=float, default=0.2, help="Validation set ratio")
    
    args = parser.parse_args()
    
    logger.info("=" * 80)
    logger.info("Stage 4 Model Trainer")
    logger.info("=" * 80)
    
    trainer = Stage4ModelTrainer(
        data_path=args.data,
        output_dir=args.output,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
    )
    
    X, y, feature_names = trainer.load_data()
    trainer.feature_names = feature_names
    
    if len(np.unique(y)) < 2:
        logger.error("Need at least 2 classes for binary classification")
        return
    
    trainer.train(X, y)
    trainer.save_model()
    
    logger.info("\n" + "=" * 80)
    logger.info("✓ Stage 4 Model Training Complete")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
