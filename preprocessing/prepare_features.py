
from pathlib import Path
import pandas as pd

# ==========================================
# TRAWIQ SECURITY - FEATURE PREPARATION
# ==========================================

INPUT_DIR = Path("data/processed/cleaned")
OUTPUT_DIR = Path("data/processed/prepared")

CHUNK_SIZE = 100_000

# Features proven to be constant and all-zero
DROP_FEATURES = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]


def prepare_file(file_path):

    print(f"\nPreparing: {file_path.name}")

    output_path = OUTPUT_DIR / f"prepared_{file_path.name}"

    first_chunk = True
    total_rows = 0

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        chunk.columns = chunk.columns.str.strip()

        if "Label" not in chunk.columns:
            raise ValueError("Label column is missing!")

        missing_features = [
            col for col in DROP_FEATURES
            if col not in chunk.columns
        ]

        if missing_features:
            raise ValueError(
                f"Missing expected features: {missing_features}"
            )

        # Remove only the verified constant features
        chunk = chunk.drop(columns=DROP_FEATURES)

        total_rows += len(chunk)

        chunk.to_csv(
            output_path,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False,
            encoding="utf-8"
        )

        first_chunk = False

    print(f"Rows prepared: {total_rows:,}")
    print(f"Remaining columns: 71")
    print(f"Saved to: {output_path}")


def main():

    print("=" * 60)
    print("TRAWIQ SECURITY - FEATURE PREPARATION")
    print("=" * 60)

    if not INPUT_DIR.exists():
        print("Cleaned dataset directory not found!")
        return

    files = sorted(INPUT_DIR.glob("cleaned_*.csv"))

    if not files:
        print("No cleaned datasets found!")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for file_path in files:
        prepare_file(file_path)

    print("\n" + "=" * 60)
    print("FEATURE PREPARATION COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()

