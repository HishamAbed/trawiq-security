
from pathlib import Path
from collections import defaultdict
import pandas as pd

DATA_DIR = Path("data/processed/prepared")
OUTPUT_DIR = Path("data/processed/analysis")
CHUNK_SIZE = 100_000


def analyze_duplicates():
    files = sorted(DATA_DIR.glob("prepared_*.csv"))

    if not files:
        print("No prepared datasets found!")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Store unique feature rows and their counts.
    # Label is excluded to detect identical traffic features
    # even if their labels differ.
    feature_counts = defaultdict(int)
    feature_labels = defaultdict(set)

    total_rows = 0

    print("=" * 70)
    print("TRAWIQ SECURITY - DUPLICATE ANALYSIS")
    print("=" * 70)

    for file_path in files:
        print(f"\nReading: {file_path.name}")

        for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE):
            total_rows += len(chunk)

            features = chunk.drop(columns=["Label"])

            # Hash each row based on its feature values.
            hashes = pd.util.hash_pandas_object(
                features,
                index=False
            )

            labels = chunk["Label"].astype(str).str.strip()

            for row_hash, label in zip(hashes, labels):
                key = int(row_hash)
                feature_counts[key] += 1
                feature_labels[key].add(label)

    unique_rows = len(feature_counts)
    duplicate_excess = total_rows - unique_rows

    duplicated_groups = sum(
        1 for count in feature_counts.values() if count > 1
    )

    cross_label_groups = sum(
        1 for labels in feature_labels.values() if len(labels) > 1
    )

    report = pd.DataFrame([
        {"Metric": "Total Rows", "Value": total_rows},
        {"Metric": "Unique Feature Rows", "Value": unique_rows},
        {"Metric": "Duplicate Excess Rows", "Value": duplicate_excess},
        {"Metric": "Duplicated Feature Groups", "Value": duplicated_groups},
        {"Metric": "Groups With Different Labels", "Value": cross_label_groups},
    ])

    report_path = OUTPUT_DIR / "duplicate_analysis_report.csv"
    report.to_csv(report_path, index=False)

    print("\n" + "=" * 70)
    print("DUPLICATE ANALYSIS RESULTS")
    print("=" * 70)

    print(report.to_string(index=False))

    if total_rows:
        percentage = duplicate_excess / total_rows * 100
        print(f"\nDuplicate Excess Percentage: {percentage:.4f}%")

    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    analyze_duplicates()
