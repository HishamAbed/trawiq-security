from pathlib import Path
from collections import Counter

import pandas as pd
import numpy as np


# Dataset directory
DATASET_DIR = Path("data/raw/MachineLearningCSV/MachineLearningCVE")

# Read large CSV files in chunks
CHUNK_SIZE = 100_000


def inspect_file(file_path):
    print("\n" + "=" * 70)
    print(f"File: {file_path.name}")
    print("=" * 70)

    total_rows = 0
    total_missing = 0
    total_infinity = 0

    label_counts = Counter()
    missing_per_column = Counter()
    columns = []

    try:
        for chunk in pd.read_csv(
            file_path,
            chunksize=CHUNK_SIZE,
            low_memory=True
        ):

            # Clean column names
            chunk.columns = chunk.columns.str.strip()

            if not columns:
                columns = list(chunk.columns)

            total_rows += len(chunk)

            # Count missing values
            missing = chunk.isna().sum()
            total_missing += int(missing.sum())

            for column, count in missing.items():
                missing_per_column[column] += int(count)

            # Count infinite values in numeric columns
            numeric_data = chunk.select_dtypes(include=np.number)

            infinity_count = np.isinf(numeric_data).sum().sum()
            total_infinity += int(infinity_count)

            # Count labels
            if "Label" in chunk.columns:
                labels = chunk["Label"].astype(str).str.strip()
                label_counts.update(labels.value_counts().to_dict())

        print(f"Total rows: {total_rows:,}")
        print(f"Total columns: {len(columns)}")
        print(f"Missing values: {total_missing:,}")
        print(f"Infinite values: {total_infinity:,}")

        print("\nColumns:")
        for column in columns:
            print(f" - {column}")

        print("\nLabels:")
        for label, count in label_counts.most_common():
            print(f" - {label}: {count:,}")

        print("\nColumns containing missing values:")
        for column, count in missing_per_column.items():
            if count > 0:
                print(f" - {column}: {count:,}")

        return {
            "file": file_path.name,
            "rows": total_rows,
            "columns": len(columns),
            "missing_values": total_missing,
            "infinite_values": total_infinity,
            "labels": dict(label_counts)
        }

    except Exception as error:
        print(f"Error inspecting file: {error}")
        return None


def main():
    print("=" * 70)
    print("TRAWIQ SECURITY - DATASET INSPECTOR")
    print("=" * 70)

    if not DATASET_DIR.exists():
        print(f"\nDataset directory not found: {DATASET_DIR}")
        return

    csv_files = list(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        print("\nNo CSV files found.")
        return

    print(f"\nFound {len(csv_files)} CSV files.")

    results = []

    for file_path in sorted(csv_files):
        result = inspect_file(file_path)

        if result:
            results.append(result)

    if results:
        report = pd.DataFrame(results)

        output_dir = Path("data/processed")
        output_dir.mkdir(parents=True, exist_ok=True)

        report_path = output_dir / "dataset_inspection_report.csv"
        report.to_csv(report_path, index=False)

        print("\n" + "=" * 70)
        print("INSPECTION COMPLETED")
        print("=" * 70)

        print(f"Files inspected: {len(results)}")
        print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()