
from pathlib import Path
import json
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data" / "processed" / "prepared"
ANALYSIS_DIR = BASE_DIR / "data" / "processed" / "analysis"
OUTPUT_DIR = BASE_DIR / "data" / "processed" / "ml_ready"

CANDIDATES_FILE = ANALYSIS_DIR / "exact_conflicting_label_examples.csv"

REPORT_FILE = ANALYSIS_DIR / "ml_dataset_report.csv"

CHUNK_SIZE = 100_000


def main():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    candidates = pd.read_csv(
        CANDIDATES_FILE,
        dtype={"row_hash": str, "feature_key": str}
    )

    conflicting_hashes = set(candidates["row_hash"])
    conflicting_features = set(candidates["feature_key"])

    files = sorted(DATA_DIR.glob("prepared_*.csv"))

    if not files:
        raise FileNotFoundError("Prepared datasets not found.")

    report = []

    total_removed = 0
    total_kept = 0

    print("Starting ML dataset preparation...")

    for index, file_path in enumerate(files, start=1):

        print(f"\n[{index}/{len(files)}] Processing: {file_path.name}")

        output_file = OUTPUT_DIR / f"ml_ready_{file_path.name}"

        if output_file.exists():
            raise FileExistsError(
                f"Output already exists: {output_file}. "
                "Move or rename the old output before running again."
            )

        rows_processed = 0
        rows_removed = 0
        rows_kept = 0
        first_chunk = True

        for chunk in pd.read_csv(
            file_path,
            chunksize=CHUNK_SIZE
        ):

            chunk.columns = chunk.columns.str.strip()

            labels = chunk["Label"].astype(str).str.strip()

            features = chunk.drop(columns=["Label"])

            hashes = pd.util.hash_pandas_object(
                features,
                index=False
            ).map(str)

            # Only inspect rows with candidate hashes
            candidate_mask = hashes.isin(conflicting_hashes)

            remove_mask = pd.Series(
                False,
                index=chunk.index
            )

            if candidate_mask.any():

                candidate_features = features.loc[candidate_mask]

                exact_keys = []

                for values in candidate_features.itertuples(
                    index=False,
                    name=None
                ):
                    exact_keys.append(
                        json.dumps(
                            [float(value) for value in values],
                            separators=(",", ":"),
                            allow_nan=False
                        )
                    )

                exact_mask = pd.Series(
                    exact_keys,
                    index=candidate_features.index
                ).isin(conflicting_features)

                remove_mask.loc[exact_mask.index] = exact_mask

            kept_chunk = chunk.loc[~remove_mask]

            # Write CSV header once per output file
            if first_chunk:
                kept_chunk.head(0).to_csv(
                    output_file,
                    index=False
                )
                first_chunk = False

            if not kept_chunk.empty:
                kept_chunk.to_csv(
                    output_file,
                    mode="a",
                    header=False,
                    index=False
                )

            removed = int(remove_mask.sum())
            kept = len(kept_chunk)

            rows_processed += len(chunk)
            rows_removed += removed
            rows_kept += kept

        total_removed += rows_removed
        total_kept += rows_kept

        report.append({
            "file": file_path.name,
            "original_rows": rows_processed,
            "removed_conflicting_rows": rows_removed,
            "remaining_rows": rows_kept
        })

        print(f"Original rows: {rows_processed:,}")
        print(f"Removed rows: {rows_removed:,}")
        print(f"Remaining rows: {rows_kept:,}")

    report.append({
        "file": "TOTAL",
        "original_rows": total_removed + total_kept,
        "removed_conflicting_rows": total_removed,
        "remaining_rows": total_kept
    })

    pd.DataFrame(report).to_csv(
        REPORT_FILE,
        index=False
    )

    print("\nML dataset preparation completed!")
    print(f"Total removed: {total_removed:,}")
    print(f"Total remaining: {total_kept:,}")
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"Report: {REPORT_FILE}")


if __name__ == "__main__":
    main()
