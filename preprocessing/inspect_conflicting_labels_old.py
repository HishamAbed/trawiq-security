
from pathlib import Path
import pandas as pd

DATA_DIR = Path("data/processed/prepared")
OUTPUT_DIR = Path("data/processed/analysis")
CHUNK_SIZE = 100_000


def inspect_conflicting_labels():
    files = sorted(DATA_DIR.glob("prepared_*.csv"))

    if not files:
        print("No prepared datasets found!")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    group_counts = {}
    group_sources = {}
    examples = {}

    print("=" * 70)
    print("TRAWIQ SECURITY - FAST CONFLICTING LABEL INSPECTION")
    print("=" * 70)

    for file_number, file_path in enumerate(files, start=1):
        print(f"\n[{file_number}/{len(files)}] Reading: {file_path.name}")

        for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE):
            features = chunk.drop(columns=["Label"])

            hashes = pd.util.hash_pandas_object(
                features,
                index=False
            ).to_numpy()

            labels = chunk["Label"].astype(str).str.strip().to_numpy()

            temp = pd.DataFrame({
                "hash": hashes,
                "label": labels
            })

            counts = temp.groupby(
                ["hash", "label"],
                sort=False
            ).size()

            for (key, label), count in counts.items():
                key = int(key)

                if key not in group_counts:
                    group_counts[key] = {}

                group_counts[key][label] = (
                    group_counts[key].get(label, 0) + int(count)
                )

            # Record source file for each hash and label.
            for key, label in temp.drop_duplicates().itertuples(
                index=False,
                name=None
            ):
                key = int(key)

                if key not in group_sources:
                    group_sources[key] = {}

                if label not in group_sources[key]:
                    group_sources[key][label] = set()

                group_sources[key][label].add(file_path.name)

            # Keep only one representative example per hash/label.
            unique_examples = temp.drop_duplicates(
                ["hash", "label"]
            )

            for key, label in unique_examples.itertuples(
                index=False,
                name=None
            ):
                key = int(key)
                example_key = (key, label)

                if example_key not in examples:
                    row_index = temp.index[
                        (temp["hash"] == key) &
                        (temp["label"] == label)
                    ][0]

                    examples[example_key] = chunk.iloc[
                        row_index
                    ].to_dict()

    conflicting = {
        key: counts
        for key, counts in group_counts.items()
        if len(counts) > 1
    }

    summary_rows = []
    example_rows = []

    for key, counts in conflicting.items():
        all_sources = sorted({
            source
            for label_sources in group_sources[key].values()
            for source in label_sources
        })

        summary_rows.append({
            "Feature_Hash": key,
            "Labels": " | ".join(sorted(counts)),
            "Label_Counts": " | ".join(
                f"{label}: {count}"
                for label, count in sorted(counts.items())
            ),
            "Total_Rows": sum(counts.values()),
            "Sources": " | ".join(all_sources)
        })

        for label, count in counts.items():
            row = {
                "Feature_Hash": key,
                "Label": label,
                "Occurrences": count,
                "Sources": " | ".join(
                    sorted(group_sources[key][label])
                )
            }

            row.update(examples[(key, label)])
            example_rows.append(row)

    summary = pd.DataFrame(summary_rows)
    example_report = pd.DataFrame(example_rows)

    if not summary.empty:
        summary = summary.sort_values(
            "Total_Rows",
            ascending=False
        )

    summary_path = OUTPUT_DIR / "conflicting_label_groups.csv"
    examples_path = OUTPUT_DIR / "conflicting_label_examples.csv"

    summary.to_csv(summary_path, index=False)
    example_report.to_csv(examples_path, index=False)

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print("Conflicting groups:", len(conflicting))
    print("Example rows:", len(example_report))

    if not summary.empty:
        print("\nTop 10 conflicting groups:")
        print(summary.head(10).to_string(index=False))

    print(f"\nSaved: {summary_path}")
    print(f"Saved: {examples_path}")


if __name__ == "__main__":
    inspect_conflicting_labels()
