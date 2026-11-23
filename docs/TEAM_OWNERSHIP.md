# Team Ownership

| Member | Primary area | Expected deliverables |
|---|---|---|
| Member 1 | `src/trawiq/capture/` | Capture adapter, source configuration, capture tests |
| Member 2 | `src/trawiq/preprocessing/` | Validation, normalization, feature extraction, tests |
| Member 3 | `src/trawiq/detection/` | Detection rules, rule documentation, tests |
| Member 4 | `src/trawiq/ml_engine/` | Training, prediction, evaluation, reproducibility notes |
| Member 5 | `tests/`, documentation, integration support | Contract tests, integration tests, test reports, documentation coordination |

## Shared responsibilities
- Every member reviews the contract and understands upstream/downstream interfaces.
- Member 5 coordinates integration and testing; this does not remove testing
  responsibility from module owners.
- One person should be nominated as repository maintainer / integration owner.
- No member owns `main`; changes enter through reviewed Pull Requests.
