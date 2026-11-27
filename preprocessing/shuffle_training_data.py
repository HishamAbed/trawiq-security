
from pathlib import Path
import pandas as pd
import random
import gc

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "processed" / "splits" / "train.csv"
OUTPUT_DIR = BASE_DIR / "data" / "processed" / "shuffled"
OUTPUT_FILE = OUTPUT_DIR / "train_shuffled.csv"

CHUNK_SIZE = 50_000
RANDOM_STATE = 42


def main():
    print("=" * 60)
    print("TRAWIQ SECURITY - TRAINING DATA SHUFFLING")
    print("=" * 60)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Training file not found: {INPUT_FILE}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if OUTPUT_FILE.exists():
        raise FileExistsError(
            f"Output already exists: {OUTPUT_FILE}\n"
            "Rename or remove it before running again."
        )

    random.seed(RANDOM_STATE)

    temp_dir = OUTPUT_DIR / "temp_chunks"
    temp_dir.mkdir(exist_ok=True)

    chunk_files = []

    try:
        print("\nStep 1: Reading and shuffling chunks...")

        reader = pd.read_csv(INPUT_FILE, chunksize=CHUNK_SIZE)

        for index, chunk in enumerate(reader):
            chunk = chunk.sample(
                frac=1,
                random_state=RANDOM_STATE + index
            )

            chunk_file = temp_dir / f"chunk_{index:04d}.csv"
            chunk.to_csv(chunk_file, index=False)

            chunk_files.append(chunk_file)

            print(
                f"Processed chunk {index + 1} | "
                f"Rows: {len(chunk):,}"
            )

            del chunk
            gc.collect()

        print("\nStep 2: Randomizing chunk order...")

        random.shuffle(chunk_files)

        print("\nStep 3: Combining shuffled chunks...")

        for index, chunk_file in enumerate(chunk_files):
            chunk = pd.read_csv(chunk_file)

            chunk.to_csv(
                OUTPUT_FILE,
                mode="a",
                header=(index == 0),
                index=False
            )

            del chunk
            gc.collect()

            print(f"Combined chunk {index + 1}/{len(chunk_files)}")

        print("\nStep 4: Cleaning temporary files...")

        for chunk_file in chunk_files:
            chunk_file.unlink()

        temp_dir.rmdir()

        output_size = OUTPUT_FILE.stat().st_size / (1024 ** 3)

        print("\n" + "=" * 60)
        print("SHUFFLING COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print(f"Output: {OUTPUT_FILE}")
        print(f"Chunks: {len(chunk_files)}")
        print(f"Output size: {output_size:.2f} GB")

    except Exception:
        print("\nERROR: Shuffling did not complete.")
        print("Temporary files have been preserved for inspection.")
        raise


if __name__ == "__main__":
    main()
