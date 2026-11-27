
from pathlib import Path
from collections import Counter

import pandas as pd
import numpy as np

DATA_DIR = Path("data/processed/cleaned")
CHUNK_SIZE = 100_000


def validate_file(file_path):
    print("\n" + "=" * 60)
    print(f"Checking: {file_path.name}")
    print("=" * 60)

    total_rows = 0
    total_missing = 0
    total_infinity = 0
    total_non_numeric = 0
    label_counts = Counter()
    column_count = 0

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):
        chunk.columns = chunk.columns.str.strip()

        total_rows += len(chunk)
        column_count = len(chunk.columns)

        if "Label" not in chunk.columns:
            raise ValueError("Label column is missing!")

        labels = chunk["Label"].astype(str).str.strip()
        label_counts.update(labels.value_counts().to_dict())

        features = chunk.drop(columns=["Label"])

        numeric = features.apply(pd.to_numeric, errors="coerce")

        total_non_numeric += int(
            (numeric.isna() & features.notna()).sum().sum()
        )

        total_missing += int(numeric.isna().sum().sum())

        total_infinity += int(
            np.isinf(numeric.to_numpy(dtype=float)).sum()
        )

    print(f"Rows: {total_rows:,}")
    print(f"Columns: {column_count}")
    print(f"Missing feature values: {total_missing:,}")
    print(f"Infinite values: {total_infinity:,}")
    print(f"Non-numeric feature values: {total_non_numeric:,}")

    print("\nLabels:")
    for label, count in label_counts.most_common():
        print(f"  {label}: {count:,}")

    return {
        "file": file_path.name,
        "rows": total_rows,
        "columns": column_count,
        "missing_values": total_missing,
        "infinite_values": total_infinity,
        "non_numeric_values": total_non_numeric,
        "labels": dict(label_counts)
    }


def main():
    print("=" * 60)
    print("TRAWIQ SECURITY - CLEANED DATA VALIDATION")
    print("=" * 60)

    files = sorted(DATA_DIR.glob("cleaned_*.csv"))

    if not files:
        print("No cleaned CSV files found!")
        return

    results = []

    for file_path in files:
        result = validate_file(file_path)
        results.append(result)

    report = pd.DataFrame(results)

    report_path = DATA_DIR / "validation_report.csv"
    report.to_csv(report_path, index=False)

    print("\n" + "=" * 60)
    print("VALIDATION COMPLETED")
    print("=" * 60)
    print(f"Files checked: {len(results)}")
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
