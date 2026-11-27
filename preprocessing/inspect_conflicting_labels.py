
from pathlib import Path
import sqlite3
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "processed" / "prepared"
OUTPUT_DIR = BASE_DIR / "data" / "processed" / "analysis"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = OUTPUT_DIR / "conflict_analysis_temp.db"
GROUPS_OUTPUT = OUTPUT_DIR / "conflicting_label_groups.csv"
EXAMPLES_OUTPUT = OUTPUT_DIR / "conflicting_label_examples.csv"

CHUNK_SIZE = 100_000


def main():
    files = sorted(DATA_DIR.glob("prepared_*.csv"))

    if not files:
        raise FileNotFoundError(f"No prepared CSV files found in {DATA_DIR}")

    connection = sqlite3.connect(DB_PATH)

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS label_counts (
                row_hash TEXT NOT NULL,
                label TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (row_hash, label)
            )
        """)

        connection.commit()

        for file_index, file_path in enumerate(files, start=1):
            print(f"\n[{file_index}/{len(files)}] Reading: {file_path.name}")

            for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE):
                chunk.columns = chunk.columns.str.strip()

                if "Label" not in chunk.columns:
                    raise ValueError(f"Label column missing in {file_path.name}")

                labels = chunk["Label"].astype(str).str.strip()
                features = chunk.drop(columns=["Label"])

                hashes = pd.util.hash_pandas_object(
                    features,
                    index=False
                )

                temp = pd.DataFrame({
                    "row_hash": hashes.map(str),
                    "label": labels
                })

                grouped = temp.groupby(
                    ["row_hash", "label"],
                    sort=False
                ).size()

                records = [
                    (row_hash, label, int(count))
                    for (row_hash, label), count in grouped.items()
                ]

                connection.executemany("""
                    INSERT INTO label_counts (row_hash, label, count)
                    VALUES (?, ?, ?)
                    ON CONFLICT(row_hash, label)
                    DO UPDATE SET count = count + excluded.count
                """, records)

                connection.commit()

            print(f"Finished: {file_path.name}")

        print("\nExtracting candidate conflicts...")

        query = """
            SELECT
                row_hash,
                COUNT(*) AS number_of_labels,
                SUM(count) AS total_rows
            FROM label_counts
            GROUP BY row_hash
            HAVING COUNT(*) > 1
            ORDER BY total_rows DESC
        """

        conflicts = pd.read_sql_query(query, connection)
        conflicts.to_csv(GROUPS_OUTPUT, index=False)

        examples = pd.read_sql_query("""
            SELECT row_hash, label AS Label, count
            FROM label_counts
            WHERE row_hash IN (
                SELECT row_hash
                FROM label_counts
                GROUP BY row_hash
                HAVING COUNT(*) > 1
            )
            ORDER BY row_hash, label
        """, connection)

        examples.to_csv(EXAMPLES_OUTPUT, index=False)

        print("\nAnalysis completed.")
        print(f"Candidate conflicting groups: {len(conflicts)}")
        print(f"Groups report: {GROUPS_OUTPUT}")
        print(f"Examples report: {EXAMPLES_OUTPUT}")

    finally:
        connection.close()


if __name__ == "__main__":
    main()
