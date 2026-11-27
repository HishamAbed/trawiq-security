
from pathlib import Path
from collections import Counter

import pandas as pd
import numpy as np


# ==========================================
# TRAWIQ SECURITY - FEATURE ANALYSIS
# ==========================================

DATA_DIR = Path("data/processed/cleaned")
OUTPUT_DIR = Path("data/processed/analysis")

CHUNK_SIZE = 100_000


def analyze_dataset():
    csv_files = sorted(DATA_DIR.glob("cleaned_*.csv"))

    if not csv_files:
        print("No cleaned datasets found!")
        return

    feature_stats = {}
    label_counts = Counter()

    total_rows = 0

    print("=" * 60)
    print("TRAWIQ SECURITY - FEATURE ANALYSIS")
    print("=" * 60)

    for file_path in csv_files:
        print(f"\nAnalyzing: {file_path.name}")

        for chunk in pd.read_csv(
            file_path,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ):
            total_rows += len(chunk)

            labels = chunk["Label"].astype(str)
            label_counts.update(labels.value_counts().to_dict())

            features = chunk.drop(columns=["Label"])

            for column in features.columns:
                values = pd.to_numeric(
                    features[column],
                    errors="coerce"
                ).fillna(0)

                if column not in feature_stats:
                    feature_stats[column] = {
                        "count": 0,
                        "zero_count": 0,
                        "min": float("inf"),
                        "max": float("-inf"),
                        "sum": 0.0,
                        "sum_squares": 0.0
                    }

                stats = feature_stats[column]

                stats["count"] += len(values)
                stats["zero_count"] += int((values == 0).sum())

                stats["min"] = min(
                    stats["min"],
                    float(values.min())
                )

                stats["max"] = max(
                    stats["max"],
                    float(values.max())
                )

                stats["sum"] += float(values.sum())
                stats["sum_squares"] += float(
                    (values.astype("float64") ** 2).sum()
                )

    results = []

    for column, stats in feature_stats.items():
        count = stats["count"]
        mean = stats["sum"] / count

        variance = (
            stats["sum_squares"] / count
        ) - (mean ** 2)

        variance = max(variance, 0)

        results.append({
            "feature": column,
            "mean": mean,
            "variance": variance,
            "min": stats["min"],
            "max": stats["max"],
            "zero_count": stats["zero_count"],
            "zero_percentage": (
                stats["zero_count"] / count
            ) * 100
        })

    report = pd.DataFrame(results)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    report_path = OUTPUT_DIR / "feature_analysis_report.csv"

    report.to_csv(report_path, index=False)

    print("\n" + "=" * 60)
    print("FEATURE ANALYSIS SUMMARY")
    print("=" * 60)

    print(f"Total rows: {total_rows:,}")
    print(f"Total features: {len(results)}")

    constant_features = report[
        report["variance"] == 0
    ]

    all_zero_features = report[
        report["zero_percentage"] == 100
    ]

    print(
        f"Constant features: {len(constant_features)}"
    )

    print(
        f"All-zero features: {len(all_zero_features)}"
    )

    print("\nConstant features:")
    print(
        constant_features["feature"].to_string(index=False)
    )

    print("\nAll-zero features:")
    print(
        all_zero_features["feature"].to_string(index=False)
    )

    print("\nLabel distribution:")
    for label, count in label_counts.most_common():
        print(f"{label}: {count:,}")

    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    analyze_dataset()
