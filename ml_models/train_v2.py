
from pathlib import Path
import gc
import json
import random
import shutil

import joblib
import numpy as np
import pandas as pd

from sklearn.linear_model import SGDClassifier


# ============================================================
# PATHS AND CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_FILE = (
    BASE_DIR / "data" / "processed" / "shuffled"
    / "train_shuffled.csv"
)

MODEL_DIR = BASE_DIR / "ml_models" / "saved" / "v2"

TEMP_DIR = MODEL_DIR / "temp_chunks"

BASELINE_SCALER = (
    BASE_DIR / "ml_models" / "saved" / "scaler_baseline.pkl"
)

MODEL_FILE = MODEL_DIR / "sgd_model_v2.pkl"
SCALER_FILE = MODEL_DIR / "scaler_v2.pkl"
CLASSES_FILE = MODEL_DIR / "classes_v2.json"
REPORT_FILE = MODEL_DIR / "training_report.json"

CHUNK_SIZE = 50_000
EPOCHS = 3
RANDOM_STATE = 42
TARGET_COLUMN = "Label"
DUPLICATE_COLUMN = "Fwd Header Length.1"

MAX_CLASS_WEIGHT = 10.0


# ============================================================
# DATA HELPERS
# ============================================================

def get_features(chunk):
    return chunk.drop(
        columns=[TARGET_COLUMN, DUPLICATE_COLUMN]
    )


def discover_classes():
    print("\nStep 1: Discovering classes...")

    class_counts = {}

    for chunk in pd.read_csv(
        DATA_FILE,
        usecols=[TARGET_COLUMN],
        chunksize=CHUNK_SIZE
    ):
        counts = chunk[TARGET_COLUMN].value_counts()

        for label, count in counts.items():
            class_counts[label] = (
                class_counts.get(label, 0) + int(count)
            )

    classes = np.array(sorted(class_counts.keys()))

    print(f"Number of classes: {len(classes)}")

    for label in classes:
        print(f"{label}: {class_counts[label]:,}")

    return classes, class_counts


def calculate_class_weights(classes, class_counts):
    print("\nStep 2: Calculating capped square-root weights...")

    total_samples = sum(class_counts.values())
    number_of_classes = len(classes)

    class_weights = {}

    for label in classes:
        count = class_counts[label]

        balanced_weight = (
            total_samples / (number_of_classes * count)
        )

        weight = min(
            np.sqrt(balanced_weight),
            MAX_CLASS_WEIGHT
        )

        class_weights[label] = float(weight)

        print(
            f"{label:30s} "
            f"count={count:10,d} "
            f"weight={weight:.4f}"
        )

    return class_weights


def prepare_temporary_chunks():
    print("\nStep 3: Preparing temporary training chunks...")

    TEMP_DIR.mkdir(parents=True, exist_ok=False)

    chunk_files = []

    reader = pd.read_csv(
        DATA_FILE,
        chunksize=CHUNK_SIZE
    )

    for index, chunk in enumerate(reader):
        chunk = chunk.sample(
            frac=1,
            random_state=RANDOM_STATE + index
        )

        chunk_file = TEMP_DIR / f"chunk_{index:04d}.csv"

        chunk.to_csv(chunk_file, index=False)

        chunk_files.append(chunk_file)

        print(
            f"Prepared chunk {index + 1} | "
            f"Rows: {len(chunk):,}"
        )

        del chunk
        gc.collect()

    return chunk_files


# ============================================================
# TRAINING
# ============================================================

def train_model(
    classes,
    class_weights,
    scaler,
    chunk_files
):
    print("\nStep 4: Initializing SGDClassifier...")

    model = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=0.0001,
        max_iter=1,
        learning_rate="optimal",
        random_state=RANDOM_STATE,
        class_weight=class_weights,
        tol=None
    )

    first_batch = True

    for epoch in range(EPOCHS):
        print("\n" + "=" * 60)
        print(f"EPOCH {epoch + 1}/{EPOCHS}")
        print("=" * 60)

        epoch_chunks = chunk_files.copy()

        random.Random(
            RANDOM_STATE + epoch
        ).shuffle(epoch_chunks)

        for batch_index, chunk_file in enumerate(epoch_chunks):

            chunk = pd.read_csv(chunk_file)

            # Shuffle rows again for this epoch
            chunk = chunk.sample(
                frac=1,
                random_state=(
                    RANDOM_STATE
                    + epoch * 1000
                    + batch_index
                )
            )

            X = get_features(chunk)
            y = chunk[TARGET_COLUMN]

            X_scaled = scaler.transform(X)

            if first_batch:
                model.partial_fit(
                    X_scaled,
                    y,
                    classes=classes
                )
                first_batch = False
            else:
                model.partial_fit(
                    X_scaled,
                    y
                )

            if (
                (batch_index + 1) % 10 == 0
                or batch_index + 1 == len(epoch_chunks)
            ):
                print(
                    f"Epoch {epoch + 1} | "
                    f"Batch {batch_index + 1}/"
                    f"{len(epoch_chunks)} completed"
                )

            del chunk, X, y, X_scaled
            gc.collect()

    return model


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("TRAWIQ SECURITY - ML MODEL V2")
    print("=" * 60)

    if not DATA_FILE.exists():
        raise FileNotFoundError(DATA_FILE)

    if not BASELINE_SCALER.exists():
        raise FileNotFoundError(BASELINE_SCALER)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    output_files = [
        MODEL_FILE,
        SCALER_FILE,
        CLASSES_FILE,
        REPORT_FILE
    ]

    for file in output_files:
        if file.exists():
            raise FileExistsError(
                f"Output already exists: {file}"
            )

    if TEMP_DIR.exists():
        raise FileExistsError(
            f"Temporary directory already exists: {TEMP_DIR}"
        )

    print("\nLoading baseline scaler...")

    scaler = joblib.load(BASELINE_SCALER)

    print(
        f"Scaler features: {scaler.n_features_in_}"
    )

    classes, class_counts = discover_classes()

    if len(classes) != 15:
        raise ValueError(
            f"Expected 15 classes, found {len(classes)}"
        )

    class_weights = calculate_class_weights(
        classes,
        class_counts
    )

    chunk_files = prepare_temporary_chunks()

    try:
        model = train_model(
            classes,
            class_weights,
            scaler,
            chunk_files
        )

        print("\nStep 5: Saving V2 model...")

        joblib.dump(model, MODEL_FILE)
        joblib.dump(scaler, SCALER_FILE)

        with open(CLASSES_FILE, "w", encoding="utf-8") as file:
            json.dump(
                classes.tolist(),
                file,
                ensure_ascii=False,
                indent=4
            )

        report = {
            "model": "SGDClassifier V2",
            "epochs": EPOCHS,
            "training_rows": int(sum(class_counts.values())),
            "number_of_classes": len(classes),
            "chunk_size": CHUNK_SIZE,
            "random_state": RANDOM_STATE,
            "weight_method": "sqrt_balanced_capped",
            "max_class_weight": MAX_CLASS_WEIGHT,
            "class_counts": {
                str(k): int(v)
                for k, v in class_counts.items()
            },
            "class_weights": class_weights
        }

        with open(REPORT_FILE, "w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                ensure_ascii=False,
                indent=4
            )

        print("\nStep 6: Cleaning temporary chunks...")

        shutil.rmtree(TEMP_DIR)

        print("\n" + "=" * 60)
        print("MODEL V2 TRAINING COMPLETED")
        print("=" * 60)

        print(f"Model: {MODEL_FILE}")
        print(f"Scaler: {SCALER_FILE}")
        print(f"Classes: {CLASSES_FILE}")
        print(f"Report: {REPORT_FILE}")

    except Exception:
        print("\nTraining failed.")
        print("Temporary chunks were preserved for inspection.")
        raise


if __name__ == "__main__":
    main()
