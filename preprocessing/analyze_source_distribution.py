
from pathlib import Path
from collections import defaultdict
import pandas as pd

DATA_DIR = Path("data/processed/prepared")
OUTPUT_DIR = Path("data/processed/analysis")
CHUNK_SIZE = 100_000


def analyze_source_distribution():
    distribution = defaultdict(lambda: defaultdict(int))

    files = sorted(DATA_DIR.glob("prepared_*.csv"))

    if not files:
        print("No prepared datasets found!")
        return

    print("=" * 70)
    print("TRAWIQ SECURITY - SOURCE DISTRIBUTION ANALYSIS")
    print("=" * 70)

    for file_path in files:
        print(f"\nReading: {file_path.name}")

        for chunk in pd.read_csv(
            file_path,
            usecols=["Label"],
            chunksize=CHUNK_SIZE
        ):
            counts = chunk["Label"].astype(str).str.strip().value_counts()

            for label, count in counts.items():
                distribution[label][file_path.name] += int(count)

    results = []

    for label, file_counts in distribution.items():
        row = {"Label": label}

        for file_path in files:
            row[file_path.name] = file_counts.get(file_path.name, 0)

        row["Total"] = sum(file_counts.values())
        results.append(row)

    report = pd.DataFrame(results)

    if not report.empty:
        report = report.sort_values("Total", ascending=False)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    report_path = OUTPUT_DIR / "source_distribution_report.csv"
    report.to_csv(report_path, index=False)

    print("\n" + "=" * 70)
    print("SOURCE DISTRIBUTION")
    print("=" * 70)

    print(report.to_string(index=False))

    print(f"\nTotal Classes: {len(report)}")
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    analyze_source_distribution()
