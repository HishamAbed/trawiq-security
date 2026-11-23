# Contributing to TRAWIQ Security

Thank you for contributing. The project is developed by a five-member team.

## Branch strategy
- `main`: stable, reviewed project state.
- `develop`: integration branch for completed and reviewed work.
- `feature/<short-name>`: one focused task per branch.

Examples:
- `feature/packet-capture`
- `feature/preprocessing`
- `feature/detection-rules`
- `feature/ml-engine`
- `feature/integration-tests`

## Workflow
1. Update your local `develop` branch.
2. Create a feature branch from `develop`.
3. Work only within your assigned module unless the team agrees otherwise.
4. Run tests and inspect your diff.
5. Push your feature branch.
6. Open a Pull Request targeting `develop`.
7. Request review from the integration owner.
8. Merge only after review and required checks pass.

Never commit directly to `main`. Avoid force-pushing shared branches.

## Commit messages
Use short, descriptive messages, for example:
- `feat(capture): add authorized pcap reader`
- `feat(ml): add baseline random forest trainer`
- `test(preprocessing): cover missing flow fields`
- `docs: define flow data contract`

## Pull Request checklist
- [ ] Scope is limited to the assigned task.
- [ ] Public interfaces match `docs/PROJECT_CONTRACT.md`.
- [ ] Tests were added or updated.
- [ ] Tests pass locally.
- [ ] No dataset, PCAP, model binary, secret, or local environment file was added.
- [ ] Documentation was updated when behavior or interfaces changed.
- [ ] The PR explains assumptions, limitations, and how it was tested.
