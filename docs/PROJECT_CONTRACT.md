# TRAWIQ Security — Project Contract (Draft v0.1)

This is the shared agreement between modules. Treat it as provisional until all
five members review and approve it. Update this document before changing a
shared interface.

## 1. Common conventions
- Python package: `trawiq`
- Internal modules live under `src/trawiq/`.
- Prefer typed functions and clear docstrings.
- Use UTC timestamps in ISO 8601 format when timestamps are introduced.
- Do not assume every field is available in every dataset or capture source.
- Missing, malformed, or unsupported fields must be handled explicitly.

## 2. Initial flow record

The first prototype is flow-oriented. A normalized record may contain:

| Field | Type | Required initially | Meaning |
|---|---|---:|---|
| `src_ip` | string | yes | Source IP address |
| `dst_ip` | string | yes | Destination IP address |
| `src_port` | integer or null | no | Source transport port |
| `dst_port` | integer or null | no | Destination transport port |
| `protocol` | string | yes | Normalized protocol name |
| `timestamp` | ISO 8601 string or null | no | Flow/event timestamp |
| `duration` | number or null | no | Flow duration |
| `packet_count` | integer or null | no | Number of packets |
| `bytes_sent` | integer or null | no | Bytes in the defined direction |

This is a starting example, not a final feature list. Before implementation,
the team must agree on directionality, units, null handling, and how bidirectional
flows are represented. Dataset-specific labels must not be used as model inputs.

## 3. Module responsibilities and proposed interfaces

The following signatures are proposals for discussion, not implemented guarantees.

### Capture — Member 1
- Reads an authorized PCAP or a supported traffic source.
- Emits raw packet records or flow records according to the chosen adapter.
- Must not silently capture from an interface without explicit configuration.

Proposed interface:
`read_capture(source: str) -> iterable[dict]`

### Preprocessing — Member 2
- Validates and normalizes input records.
- Converts source-specific fields to the agreed flow schema.
- Separates labels from model features to prevent data leakage.

Proposed interface:
`extract_features(records: iterable[dict]) -> list[dict]`

### Detection rules — Member 3
- Applies documented deterministic rules to normalized records.
- Returns zero or more structured findings per record.

Proposed interface:
`detect_rules(record: dict) -> list[dict]`

### ML engine — Member 4
- Trains and evaluates models using reproducible train/test splits.
- Loads a versioned model and predicts on the agreed feature schema.
- Reports model version and evaluation context.

Proposed interfaces:
`train_model(dataset, config) -> training_result`
`predict(record: dict) -> dict`

### Integration
- Calls rules and ML against compatible records.
- Preserves the source of each finding.
- Does not collapse disagreement between rule and model into a misleading single truth value.

Proposed interface:
`analyze_record(record: dict) -> dict`

## 4. Common finding shape (proposal)

A finding should include:
- `source`: `rule` or `ml`
- `detected`: boolean
- `category`: string or null
- `severity`: agreed enum or null
- `score`: numeric or null, with documented meaning
- `evidence`: list of concise supporting facts
- `model_version` or `rule_id`, where applicable

The team must agree on severity levels and score semantics before implementation.

## 5. Error handling
- Invalid input should produce a clear validation error or a documented rejected-record result.
- Modules must not hide exceptions with broad `except: pass` blocks.
- Logging must not expose credentials or unnecessary payload contents.

## 6. Testing expectations
- Each module supplies unit tests for valid, invalid, and boundary inputs.
- Integration tests use small synthetic fixtures, not private or sensitive traffic.
- Model evaluation must guard against train/test leakage and class imbalance.
- Report precision, recall, F1-score, confusion matrix, and false-positive rate
  where appropriate; accuracy alone is insufficient.

## 7. Change control
Any breaking interface change requires:
1. A proposed edit to this contract.
2. Agreement from affected module owners.
3. Updated tests and documentation in the same PR.
