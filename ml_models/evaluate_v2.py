
from pathlib import Path
import json
import gc

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score
)

BASE_DIR = Path(__file__).resolve().parent.parent

TEST_FILE = (
    BASE_DIR / "data" / "processed"
    / "splits" / "test.csv"
)

MODEL_DIR = BASE_DIR / "ml_models" / "saved" / "v2"

MODEL_FILE = MODEL_DIR / "sgd_model_v2.pkl"
SCALER_FILE = MODEL_DIR / "scaler_v2.pkl"
CLASSES_FILE = MODEL_DIR / "classes_v2.json"

REPORT_FILE = MODEL_DIR / "evaluation_report.json"
CONFUSION_FILE = MODEL_DIR / "confusion_matrix.csv"

CHUNK_SIZE = 50_000
TARGET_COLUMN = "Label"
DUPLICATE_COLUMN = "Fwd Header Length.1"


def main():

    print("=" * 60)
    print("TRAWIQ SECURITY - MODEL V2 EVALUATION")
    print("=" * 60)

    for file in [
        TEST_FILE,
        MODEL_FILE,
        SCALER_FILE,
        CLASSES_FILE
    ]:
        if not file.exists():
            raise FileNotFoundError(file)

    print("\nStep 1: Loading model and scaler...")

    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)

    with open(CLASSES_FILE, "r", encoding="utf-8") as file:
        classes = json.load(file)

    print(f"Number of classes: {len(classes)}")
    print(f"Model features: {model.n_features_in_}")

    print("\nStep 2: Predicting test data...")

    all_true = []
    all_pred = []

    total_rows = 0

    for chunk_index, chunk in enumerate(
        pd.read_csv(TEST_FILE, chunksize=CHUNK_SIZE),
        start=1
    ):

        y = chunk[TARGET_COLUMN].to_numpy()

        X = chunk.drop(
            columns=[TARGET_COLUMN, DUPLICATE_COLUMN]
        )

        X_scaled = scaler.transform(X)

        predictions = model.predict(X_scaled)

        all_true.extend(y)
        all_pred.extend(predictions)

        total_rows += len(chunk)

        print(
            f"Processed batch {chunk_index} | "
            f"Total rows: {total_rows:,}"
        )

        del chunk, X, X_scaled, y, predictions
        gc.collect()

    print("\nStep 3: Calculating metrics...")

    accuracy = accuracy_score(all_true, all_pred)

    macro_f1 = f1_score(
        all_true,
        all_pred,
        labels=classes,
        average="macro",
        zero_division=0
    )

    weighted_f1 = f1_score(
        all_true,
        all_pred,
        labels=classes,
        average="weighted",
        zero_division=0
    )

    report = classification_report(
        all_true,
        all_pred,
        labels=classes,
        target_names=classes,
        output_dict=True,
        zero_division=0
    )

    matrix = confusion_matrix(
        all_true,
        all_pred,
        labels=classes
    )

    print("\n" + "=" * 60)
    print("MODEL V2 RESULTS")
    print("=" * 60)

    print(f"Accuracy:   {accuracy:.4f}")
    print(f"Macro F1:   {macro_f1:.4f}")
    print(f"Weighted F1:{weighted_f1:.4f}")

    print("\nClassification Report:")

    print(
        classification_report(
            all_true,
            all_pred,
            labels=classes,
            target_names=classes,
            zero_division=0
        )
    )

    print("\nStep 4: Saving evaluation results...")

    matrix_df = pd.DataFrame(
        matrix,
        index=classes,
        columns=classes
    )

    matrix_df.to_csv(CONFUSION_FILE)

    results = {
        "model": "TRAWIQ Security V2",
        "test_samples": total_rows,
        "accuracy": float(accuracy),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "classification_report": report
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(
            results,
            file,
            ensure_ascii=False,
            indent=4
        )

    print(f"Evaluation report: {REPORT_FILE}")
    print(f"Confusion matrix: {CONFUSION_FILE}")

    print("\nEvaluation completed successfully!")


if __name__ == "__main__":
    main()
