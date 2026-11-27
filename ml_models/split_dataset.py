
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_DIR = BASE_DIR / "data" / "processed" / "ml_ready"
OUTPUT_DIR = BASE_DIR / "data" / "processed" / "splits"

TRAIN_FILE = OUTPUT_DIR / "train.csv"
TEST_FILE = OUTPUT_DIR / "test.csv"
REPORT_FILE = OUTPUT_DIR / "split_report.csv"

TEST_SIZE = 0.20
RANDOM_STATE = 42
CHUNK_SIZE = 100_000


def main():
    files = sorted(INPUT_DIR.glob("ml_ready_*.csv"))

    if not files:
        raise FileNotFoundError(
            f"No ML-ready CSV files found in: {INPUT_DIR}"
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Step 1: Count labels
    print("Step 1: Counting class labels...")

    class_counts = {}

    for file in files:
        for chunk in pd.read_csv(
            file,
            usecols=["Label"],
            chunksize=CHUNK_SIZE
        ):
            counts = chunk["Label"].value_counts()

            for label, count in counts.items():
                class_counts[label] = (
                    class_counts.get(label, 0) + int(count)
                )

    classes = list(class_counts.keys())
    label_to_id = {
        label: index for index, label in enumerate(classes)
    }

    total_samples = sum(class_counts.values())

    print(f"Total samples: {total_samples:,}")
    print(f"Number of classes: {len(classes)}")

    # Step 2: Read labels in the EXACT original row order
    print("\nStep 2: Preparing labels in original dataset order...")

    label_parts = []

    for file_number, file in enumerate(files, start=1):
        print(f"[{file_number}/{len(files)}] Reading labels: {file.name}")

        for chunk in pd.read_csv(
            file,
            usecols=["Label"],
            chunksize=CHUNK_SIZE
        ):
            encoded = chunk["Label"].map(label_to_id).to_numpy(
                dtype=np.int8
            )

            if (encoded < 0).any():
                raise ValueError("Unknown label found.")

            label_parts.append(encoded)

    labels = np.concatenate(label_parts)

    if len(labels) != total_samples:
        raise ValueError("Label count does not match dataset size.")

    # Step 3: Stratified split
    print("\nStep 3: Creating stratified split...")

    indices = np.arange(total_samples)

    train_indices, test_indices = train_test_split(
        indices,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=labels
    )

    train_indices.sort()
    test_indices.sort()

    print(f"Training samples: {len(train_indices):,}")
    print(f"Testing samples: {len(test_indices):,}")

    del labels, label_parts, indices

    # Step 4: Write train and test files in chunks
    print("\nStep 4: Writing split files...")

    for output_file in [TRAIN_FILE, TEST_FILE]:
        if output_file.exists():
            output_file.unlink()

    train_pointer = 0
    test_pointer = 0
    global_position = 0

    for file_number, file in enumerate(files, start=1):
        print(f"[{file_number}/{len(files)}] Processing: {file.name}")

        for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE):
            chunk_length = len(chunk)
            chunk_end = global_position + chunk_length

            train_end = np.searchsorted(
                train_indices,
                chunk_end,
                side="left"
            )

            test_end = np.searchsorted(
                test_indices,
                chunk_end,
                side="left"
            )

            local_train = (
                train_indices[train_pointer:train_end]
                - global_position
            )

            local_test = (
                test_indices[test_pointer:test_end]
                - global_position
            )

            if len(local_train) > 0:
                chunk.iloc[local_train].to_csv(
                    TRAIN_FILE,
                    mode="a",
                    header=not TRAIN_FILE.exists(),
                    index=False
                )

            if len(local_test) > 0:
                chunk.iloc[local_test].to_csv(
                    TEST_FILE,
                    mode="a",
                    header=not TEST_FILE.exists(),
                    index=False
                )

            train_pointer = train_end
            test_pointer = test_end
            global_position = chunk_end

    if global_position != total_samples:
        raise ValueError("Not all dataset rows were processed.")

    if train_pointer != len(train_indices):
        raise ValueError("Some training rows were not written.")

    if test_pointer != len(test_indices):
        raise ValueError("Some testing rows were not written.")

    # Step 5: Verify output class distribution
    print("\nStep 5: Verifying split distribution...")

    train_counts = {}
    test_counts = {}

    for chunk in pd.read_csv(
        TRAIN_FILE,
        usecols=["Label"],
        chunksize=CHUNK_SIZE
    ):
        for label, count in chunk["Label"].value_counts().items():
            train_counts[label] = (
                train_counts.get(label, 0) + int(count)
            )

    for chunk in pd.read_csv(
        TEST_FILE,
        usecols=["Label"],
        chunksize=CHUNK_SIZE
    ):
        for label, count in chunk["Label"].value_counts().items():
            test_counts[label] = (
                test_counts.get(label, 0) + int(count)
            )

    report = []

    for label, total in class_counts.items():
        train_count = train_counts.get(label, 0)
        test_count = test_counts.get(label, 0)

        report.append({
            "Label": label,
            "Total": total,
            "Train": train_count,
            "Test": test_count,
            "Train_Percentage": round(
                train_count / total * 100, 2
            ),
            "Test_Percentage": round(
                test_count / total * 100, 2
            )
        })

    pd.DataFrame(report).to_csv(
        REPORT_FILE,
        index=False
    )

    print("\nSplit completed successfully!")
    print(f"Total samples: {total_samples:,}")
    print(f"Training samples: {len(train_indices):,}")
    print(f"Testing samples: {len(test_indices):,}")
    print(f"Train file: {TRAIN_FILE}")
    print(f"Test file: {TEST_FILE}")
    print(f"Report: {REPORT_FILE}")


if __name__ == "__main__":
    main()
