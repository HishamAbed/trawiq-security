
from pathlib import Path
from collections import Counter
import pandas as pd

DATA_DIR = Path("data/processed/prepared")
OUTPUT_DIR = Path("data/processed/analysis")
CHUNK_SIZE = 100_000


def analyze_class_balance():
    label_counts = Counter()

    files = sorted(DATA_DIR.glob("prepared_*.csv"))

    if not files:
        print("No prepared datasets found!")
        return

    print("=" * 60)
    print("TRAWIQ SECURITY - CLASS BALANCE ANALYSIS")
    print("=" * 60)

    for file_path in files:
        print(f"\nReading: {file_path.name}")

        for chunk in pd.read_csv(
            file_path,
            usecols=["Label"],
            chunksize=CHUNK_SIZE
        ):
            labels = chunk["Label"].astype(str).str.strip()
            label_counts.update(labels.value_counts().to_dict())

    total = sum(label_counts.values())

    results = []

    for label, count in label_counts.most_common():
        percentage = (count / total) * 100

        results.append({
            "Label": label,
            "Count": count,
            "Percentage": round(percentage, 4)
        })

    report = pd.DataFrame(results)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    report_path = OUTPUT_DIR / "class_balance_report.csv"
    report.to_csv(report_path, index=False)

    print("\n" + "=" * 60)
    print("CLASS DISTRIBUTION")
    print("=" * 60)

    print(report.to_string(index=False))

    print("\nTotal Flows:", f"{total:,}")
    print("Total Classes:", len(label_counts))
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    analyze_class_balance()
