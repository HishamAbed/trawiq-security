
from pathlib import Path
import gc
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import SGDClassifier
from sklearn.utils.class_weight import compute_class_weight


# ==============================
# Project Configuration
# ==============================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data" / "processed" / "splits"
MODEL_DIR = BASE_DIR / "ml_models" / "saved"

TRAIN_FILE = DATA_DIR / "train.csv"

SCALER_FILE = MODEL_DIR / "scaler.pkl"
MODEL_FILE = MODEL_DIR / "sgd_model.pkl"
CLASSES_FILE = MODEL_DIR / "classes.json"

CHUNK_SIZE = 50_000
RANDOM_STATE = 42

TARGET_COLUMN = "Label"
DUPLICATE_COLUMN = "Fwd Header Length.1"


def get_features(chunk):
    """Remove target and duplicate feature."""

    return chunk.drop(
        columns=[TARGET_COLUMN, DUPLICATE_COLUMN]
    )


# ==============================
# Main Training Pipeline
# ==============================

def main():

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    if not TRAIN_FILE.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {TRAIN_FILE}"
        )

    print("=" * 60)
    print("TRAWIQ SECURITY - MODEL TRAINING")
    print("=" * 60)

    # --------------------------
    # Step 1: Discover classes
    # --------------------------

    print("\nStep 1: Discovering classes...")

    class_counts = {}

    for chunk in pd.read_csv(
        TRAIN_FILE,
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

    # --------------------------
    # Step 2: Fit scaler
    # --------------------------

    print("\nStep 2: Fitting StandardScaler...")

    scaler = StandardScaler()

    for chunk in pd.read_csv(
        TRAIN_FILE,
        chunksize=CHUNK_SIZE
    ):

        X = get_features(chunk)

        scaler.partial_fit(X)

        del X, chunk

    joblib.dump(scaler, SCALER_FILE)

    print("Scaler fitted and saved.")

    gc.collect()

    # --------------------------
    # Step 3: Calculate weights
    # --------------------------

    print("\nStep 3: Calculating class weights...")

    counts_array = np.array(
        [class_counts[label] for label in classes],
        dtype=np.float64
    )
    weights = counts_array.sum() / (
    len(classes) * counts_array
)

    # Balanced class weight formula:
    # total_samples / (number_of_classes * class_samples)

    class_weights = {
        label: float(weight)
        for label, weight in zip(classes, weights)
    }

    print("Class weights calculated.")

    # --------------------------
    # Step 4: Initialize model
    # --------------------------

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

    # --------------------------
    # Step 5: Train incrementally
    # --------------------------

    print("\nStep 5: Training model...")

    first_batch = True
    batch_number = 0

    for chunk in pd.read_csv(
        TRAIN_FILE,
        chunksize=CHUNK_SIZE
    ):

        batch_number += 1

        X = get_features(chunk)
        y = chunk[TARGET_COLUMN].to_numpy()

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

        print(
            f"Batch {batch_number}: "
            f"{len(chunk):,} samples processed"
        )

        del X, X_scaled, y, chunk

        gc.collect()

    # --------------------------
    # Step 6: Save model
    # --------------------------

    print("\nStep 6: Saving model...")

    joblib.dump(model, MODEL_FILE)

    with open(CLASSES_FILE, "w", encoding="utf-8") as file:
        json.dump(
            classes.tolist(),
            file,
            ensure_ascii=False,
            indent=4
        )

    print("\n" + "=" * 60)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print(f"Model: {MODEL_FILE}")
    print(f"Scaler: {SCALER_FILE}")
    print(f"Classes: {CLASSES_FILE}")


if __name__ == "__main__":
    main()
