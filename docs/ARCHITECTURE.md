# TRAWIQ Security — Architecture

## Purpose
TRAWIQ Security aims to monitor and analyze authorized network traffic, identify
suspicious activity using deterministic detection rules and machine-learning
models, and present explainable investigation results.

This document describes the intended module boundaries. It does not claim that
these capabilities are implemented yet.

## High-level flow

Authorized traffic / approved dataset
    -> capture
    -> preprocessing
    -> parallel analysis:
         -> detection rules
         -> ML engine
    -> integration / correlation
    -> (future) API and dashboard

## Modules and ownership

| Module | Initial owner | Responsibility |
|---|---|---|
| `capture` | Member 1 | Read authorized packet captures or receive approved traffic; produce documented raw records |
| `preprocessing` | Member 2 | Validate, normalize, transform, and extract agreed features |
| `detection` | Member 3 | Apply documented deterministic detection rules |
| `ml_engine` | Member 4 | Train, evaluate, and run ML models |
| `integration` | Integration owner / team | Call modules, normalize findings, and combine results |
| `tests` | Member 5 with all members | Unit, contract, and integration tests |

## Important design decisions
- Use a flow-oriented normalized record as the initial hand-off between capture
  and preprocessing. The exact fields must be agreed and versioned in
  `PROJECT_CONTRACT.md`.
- Rules and ML should analyze the same normalized feature record where their
  required features overlap.
- Rule findings and ML predictions remain separate evidence sources. Integration
  combines them; it must not silently treat model confidence as a calibrated
  probability.
- Keep dataset-specific column names inside adapters rather than spreading them
  across the application.
- The dashboard and live capture are later milestones, not prerequisites for
  validating the first offline prototype.

## Future extension points
- `api/`: backend API after the core engine stabilizes.
- `dashboard/`: user interface after API/data contracts stabilize.
- `investigation/`: attack-path or incident-correlation features after event
  relationships are defined.
