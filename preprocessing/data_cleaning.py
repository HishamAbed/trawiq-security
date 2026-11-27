
from pathlib import Path
import re

import pandas as pd
import numpy as np


# ==========================================
# TRAWIQ SECURITY - DATA CLEANING
# ==========================================

DATASET_DIR = Path(
    "data/raw/MachineLearningCSV/MachineLearningCVE"
)

OUTPUT_DIR = Path("data/processed/cleaned")

CHUNK_SIZE = 100_000


def normalize_label(label):
    """Normalize attack labels into consistent names."""

    original = str(label).strip()

    # Remove unusual encoding characters by normalizing
    # the label into lowercase words.
    normalized = re.sub(
        r"[^a-z0-9]+",
        " ",
        original.lower()
    ).strip()

    # Standard labels
    label_mapping = {
        "benign": "BENIGN",
        "ddos": "DDoS",
        "portscan": "PortScan",
        "bot": "Bot",
        "infiltration": "Infiltration",
        "ftp patator": "FTP-Patator",
        "ssh patator": "SSH-Patator",
        "dos hulk": "DoS Hulk",
        "dos slowloris": "DoS slowloris",
        "dos slowhttptest": "DoS Slowhttptest",
        "dos goldeneye": "DoS GoldenEye",
        "heartbleed": "Heartbleed",
        "web attack brute force": "Web Attack - Brute Force",
        "web attack xss": "Web Attack - XSS",
        "web attack sql injection": "Web Attack - SQL Injection",
    }

    return label_mapping.get(normalized, original)


def clean_chunk(df):
    """Clean one chunk of network traffic data."""

    # 1. Clean column names
    df.columns = df.columns.str.strip()

    # 2. Handle missing labels BEFORE converting to strings
    if "Label" not in df.columns:
        raise ValueError("Label column is missing!")

    df = df.dropna(subset=["Label"]).copy()

    df["Label"] = df["Label"].astype(str).str.strip()

    df = df[df["Label"] != ""]

    # 3. Normalize attack labels
    df["Label"] = df["Label"].apply(normalize_label)

    # 4. Convert features to numeric values
    feature_columns = [
        column for column in df.columns
        if column != "Label"
    ]

    for column in feature_columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    # 5. Replace infinite values with NaN
    df[feature_columns] = df[feature_columns].replace(
        [np.inf, -np.inf],
        np.nan
    )

    # 6. Replace missing feature values with zero
    df[feature_columns] = df[feature_columns].fillna(0)

    return df


def clean_file(file_path):
    print(f"\nCleaning: {file_path.name}")

    output_path = OUTPUT_DIR / f"cleaned_{file_path.name}"

    first_chunk = True
    total_input = 0
    total_output = 0

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):
        total_input += len(chunk)

        cleaned_chunk = clean_chunk(chunk)

        total_output += len(cleaned_chunk)

        cleaned_chunk.to_csv(
            output_path,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False,
            encoding="utf-8"
        )

        first_chunk = False

    print(f"Input rows: {total_input:,}")
    print(f"Output rows: {total_output:,}")
    print(f"Removed rows: {total_input - total_output:,}")
    print(f"Saved to: {output_path}")


def main():
    print("=" * 60)
    print("TRAWIQ SECURITY - DATA CLEANING")
    print("=" * 60)

    if not DATASET_DIR.exists():
        print(f"Dataset directory not found: {DATASET_DIR}")
        return

    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        print("No CSV files found!")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for file_path in csv_files:
        clean_file(file_path)

    print("\n" + "=" * 60)
    print("DATA CLEANING COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
