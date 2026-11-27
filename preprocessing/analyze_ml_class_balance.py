
from pathlib import Path
from collections import Counter
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data" / "processed" / "ml_ready"
OUTPUT_DIR = BASE_DIR / "data" / "processed" / "analysis"

OUTPUT_FILE = OUTPUT_DIR / "ml_class_balance_report.csv"

CHUNK_SIZE = 100_000


def main():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    class_counts = Counter()

    files = sorted(DATA_DIR.glob("ml_ready_*.csv"))

    if not files:
        raise FileNotFoundError("ML-ready files not found.")

    for index, file_path in enumerate(files, start=1):

        print(f"[{index}/{len(files)}] Reading: {file_path.name}")

        for chunk in pd.read_csv(
            file_path,
            usecols=["Label"],
            chunksize=CHUNK_SIZE
        ):
            counts = chunk["Label"].value_counts()
            class_counts.update(counts.to_dict())

    total = sum(class_counts.values())

    report = []

    for label, count in class_counts.most_common():

        report.append({
            "Label": label,
            "Samples": count,
            "Percentage": round(count / total * 100, 4)
        })

    report_df = pd.DataFrame(report)

    report_df.to_csv(OUTPUT_FILE, index=False)

    print("\nFinal Class Balance Analysis Completed!")
    print(f"Total samples: {total:,}")
    print(f"Number of classes: {len(class_counts)}")
    print(f"Report: {OUTPUT_FILE}")

    print("\nClass Distribution:")
    print(report_df.to_string(index=False))


if __name__ == "__main__":
    main()
