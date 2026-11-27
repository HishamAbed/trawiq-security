
import json
import joblib
import pandas as pd

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# ==========================
# Paths and Configuration
# ==========================

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

SAVED_DIR = BASE_DIR / "saved"

MODEL_FILE = SAVED_DIR / "sgd_model.pkl"
SCALER_FILE = SAVED_DIR / "scaler.pkl"
CLASSES_FILE = SAVED_DIR / "classes.json"

TEST_FILE = (
    PROJECT_DIR
    / "data"
    / "processed"
    / "splits"
    / "test.csv"
)

CHUNK_SIZE = 50000


# ==========================
# Main Evaluation Function
# ==========================

def main():

    print("=" * 60)
    print("TRAWIQ SECURITY - MODEL EVALUATION")
    print("=" * 60)

    # Step 1: Check files

    print("\nStep 1: Checking required files...")

    required_files = [
        MODEL_FILE,
        SCALER_FILE,
        CLASSES_FILE,
        TEST_FILE,
    ]

    for file_path in required_files:
        if not file_path.exists():
            raise FileNotFoundError(
                f"Required file not found: {file_path}"
            )

    print("All required files found.")

    # Step 2: Load model and scaler

    print("\nStep 2: Loading model and scaler...")

    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)

    with open(CLASSES_FILE, "r", encoding="utf-8") as file:
        classes = json.load(file)

    print("Model loaded successfully.")
    print("Scaler loaded successfully.")
    print(f"Number of classes: {len(classes)}")

    # Step 3: Evaluate test data

    print("\nStep 3: Evaluating test dataset...")

    y_true_parts = []
    y_pred_parts = []

    total_samples = 0
    batch_number = 0

    for chunk in pd.read_csv(
        TEST_FILE,
        chunksize=CHUNK_SIZE
    ):

        batch_number += 1

        y_true = chunk["Label"].astype(str)

        X_test = chunk.drop(
            columns=[
                "Label",
                "Fwd Header Length.1"
            ],
            errors="ignore"
        )

        X_scaled = scaler.transform(X_test)

        predictions = model.predict(X_scaled)

        y_true_parts.extend(y_true.tolist())
        y_pred_parts.extend(predictions.tolist())

        total_samples += len(chunk)

        print(
            f"Batch {batch_number}: "
            f"{len(chunk):,} samples evaluated"
        )

    # Step 4: Calculate metrics

    print("\nStep 4: Calculating performance metrics...")

    accuracy = accuracy_score(
        y_true_parts,
        y_pred_parts
    )

    print("\n" + "=" * 60)
    print("MODEL PERFORMANCE")
    print("=" * 60)

    print(
        f"\nAccuracy: {accuracy:.4f} "
        f"({accuracy * 100:.2f}%)"
    )

    # Classification report

    print("\nClassification Report:")

    report = classification_report(
        y_true_parts,
        y_pred_parts,
        labels=classes,
        target_names=classes,
        zero_division=0
    )

    print(report)

    # Confusion matrix

    print("\nConfusion Matrix:")

    matrix = confusion_matrix(
        y_true_parts,
        y_pred_parts,
        labels=classes
    )

    print("\nClass Order:")

    for index, class_name in enumerate(classes):
        print(f"{index}: {class_name}")

    print("\nMatrix:")

    print(matrix)

    # Final summary

    print("\n" + "=" * 60)
    print("EVALUATION COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print(f"Total samples evaluated: {total_samples:,}")
    print(f"Total classes: {len(classes)}")


# ==========================
# Run Program
# ==========================

if __name__ == "__main__":
    main()
