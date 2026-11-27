
from pathlib import Path
import sqlite3
import json
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data" / "processed" / "prepared"
ANALYSIS_DIR = BASE_DIR / "data" / "processed" / "analysis"

CANDIDATES_FILE = ANALYSIS_DIR / "conflicting_label_groups.csv"

DB_FILE = ANALYSIS_DIR / "exact_verification_temp.db"

GROUPS_OUTPUT = ANALYSIS_DIR / "exact_conflicting_label_groups.csv"
EXAMPLES_OUTPUT = ANALYSIS_DIR / "exact_conflicting_label_examples.csv"

CHUNK_SIZE = 100_000


def main():

    print("Loading candidate hashes...")

    candidates_df = pd.read_csv(
        CANDIDATES_FILE,
        dtype={"row_hash": str}
    )

    candidate_hashes = set(candidates_df["row_hash"])

    print(f"Candidate hashes loaded: {len(candidate_hashes)}")

    files = sorted(DATA_DIR.glob("prepared_*.csv"))

    if not files:
        raise FileNotFoundError("Prepared CSV files not found.")

    connection = sqlite3.connect(DB_FILE)

    try:

        connection.execute("DROP TABLE IF EXISTS exact_rows")

        connection.execute("""
            CREATE TABLE exact_rows (
                row_hash TEXT NOT NULL,
                feature_key TEXT NOT NULL,
                label TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (feature_key, label)
            )
        """)

        connection.commit()

        for file_index, file_path in enumerate(files, start=1):

            print(f"\n[{file_index}/{len(files)}] Reading: {file_path.name}")

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

                mask = hashes.isin(candidate_hashes)

                if not mask.any():
                    continue

                selected_features = features.loc[mask]
                selected_labels = labels.loc[mask]
                selected_hashes = hashes.loc[mask]

                records = []

                for row_hash, label, values in zip(
                    selected_hashes,
                    selected_labels,
                    selected_features.itertuples(
                        index=False,
                        name=None
                    )
                ):

                    # Exact feature signature using parsed numeric values
                    feature_key = json.dumps(
                        [float(value) for value in values],
                        separators=(",", ":"),
                        allow_nan=False
                    )

                    records.append((
                        row_hash,
                        feature_key,
                        label,
                        1
                    ))

                connection.executemany("""
                    INSERT INTO exact_rows
                    (row_hash, feature_key, label, count)
                    VALUES (?, ?, ?, ?)

                    ON CONFLICT(feature_key, label)
                    DO UPDATE SET count = count + 1
                """, records)

                connection.commit()

            print(f"Finished: {file_path.name}")

        print("\nChecking exact feature matches...")

        groups = pd.read_sql_query("""
            SELECT
                MIN(row_hash) AS row_hash,
                feature_key,
                COUNT(DISTINCT label) AS number_of_labels,
                SUM(count) AS total_rows
            FROM exact_rows
            GROUP BY feature_key
            HAVING COUNT(DISTINCT label) > 1
            ORDER BY total_rows DESC
        """, connection)

        groups.to_csv(GROUPS_OUTPUT, index=False)

        examples = pd.read_sql_query("""
            SELECT
                row_hash,
                label AS Label,
                count,
                feature_key
            FROM exact_rows
            WHERE feature_key IN (
                SELECT feature_key
                FROM exact_rows
                GROUP BY feature_key
                HAVING COUNT(DISTINCT label) > 1
            )
            ORDER BY row_hash, label
        """, connection)

        examples.to_csv(EXAMPLES_OUTPUT, index=False)

        print("\nExact verification completed!")
        print(f"True conflicting feature groups: {len(groups)}")
        print(f"Groups report: {GROUPS_OUTPUT}")
        print(f"Examples report: {EXAMPLES_OUTPUT}")

    finally:
        connection.close()


if __name__ == "__main__":
    main()
