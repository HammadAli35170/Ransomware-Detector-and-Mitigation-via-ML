# PowerShell script for enhanced model training
# Usage: .\train_enhanced.ps1

$dataset = "data/fyp_dataset_v3_realistic_20260127.parquet"
$output = "models/model_enhanced.txt"

Write-Host "Starting enhanced model training..." -ForegroundColor Green
Write-Host "Dataset: $dataset" -ForegroundColor Cyan
Write-Host "Output: $output" -ForegroundColor Cyan

python train_ml_model_v11.py `
  --dataset $dataset `
  --output $output `
  --use-optuna `
  --optuna-trials 50 `
  --use-ensemble `
  --ensemble-size 5 `
  --use-xgboost `
  --cv-folds 5 `
  --threshold-metric f1_recall `
  --min-recall 0.9

Write-Host "Training complete!" -ForegroundColor Green
