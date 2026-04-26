#!/usr/bin/env python3
"""
Parquet to JSONL Converter

Converts your FYP ransomware detection dataset from Parquet to JSON Lines format.

Usage:
    python parquet_to_jsonl.py --input data/fyp_dataset_v3/fyp_dataset.parquet --output data/fyp_dataset_v3/fyp_dataset.jsonl

Features:
- Handles large files efficiently
- Preserves all features and labels
- Pretty progress bar
- Optional sampling for quick testing
"""

import argparse
import pandas as pd
from pathlib import Path
from tqdm import tqdm
import sys

def convert_parquet_to_jsonl(
    input_path: str,
    output_path: str,
    sample: int = None,
    chunk_size: int = 1000
) -> None:
    """
    Convert Parquet file to JSONL efficiently using chunking.
    
    Args:
        input_path: Path to input .parquet file
        output_path: Path to output .jsonl file
        sample: If set, randomly sample N rows (useful for testing)
        chunk_size: Number of rows per chunk (for memory efficiency)
    """
    input_file = Path(input_path)
    output_file = Path(output_path)
    
    if not input_file.exists():
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading Parquet file: {input_path}")
    print(f"Output will be saved to: {output_path}")
    
    # Read Parquet (with optional sampling)
    try:
        if sample:
            print(f"Sampling {sample} rows for quick testing...")
            df = pd.read_parquet(input_file).sample(n=sample, random_state=42)
        else:
            df = pd.read_parquet(input_file)
    except Exception as e:
        print(f"Failed to read Parquet file: {e}")
        sys.exit(1)
    
    total_rows = len(df)
    print(f"Dataset loaded: {total_rows:,} samples, {len(df.columns)} features")
    
    if 'label' in df.columns:
        malicious_count = df['label'].sum()
        print(f"Label distribution: {total_rows - malicious_count:,} benign, {malicious_count:,} malicious")
    
    print(f"Converting to JSONL (chunk_size={chunk_size})...")
    
    # Write in chunks to avoid memory issues
    with open(output_file, 'w', encoding='utf-8') as f:
        for start in tqdm(range(0, total_rows, chunk_size), desc="Progress", unit="chunk"):
            end = min(start + chunk_size, total_rows)
            chunk = df.iloc[start:end]
            
            # Convert chunk to JSON Lines and write
            json_lines = chunk.to_json(orient="records", lines=True, date_format="iso")
            f.write(json_lines)
    
    print(f"\nConversion complete!")
    print(f"JSONL file saved: {output_path}")
    print(f"Size: {output_file.stat().st_size / (1024*1024):.1f} MB")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert FYP Parquet dataset to JSON Lines (.jsonl)"
    )
    parser.add_argument(
        "--input",
        "-i",
        default="data/fyp_dataset_v3/fyp_dataset.parquet",
        help="Path to input Parquet file"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="data/fyp_dataset_v3/fyp_dataset.jsonl",
        help="Path to output JSONL file"
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        help="Randomly sample N rows (for quick testing)"
    )
    parser.add_argument(
        "--chunk",
        type=int,
        default=1000,
        help="Chunk size for memory-efficient writing"
    )
    
    args = parser.parse_args()
    
    convert_parquet_to_jsonl(
        input_path=args.input,
        output_path=args.output,
        sample=args.sample,
        chunk_size=args.chunk
    )