## What does this PR change?

<!-- A short description of the change and why it is needed. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New detection rule
- [ ] New feature / CLI option
- [ ] Documentation
- [ ] Tests / CI / refactoring

## How was it tested?

<!-- Commands you ran and anything notable in the output. -->

## Checklist

- [ ] `pytest` passes locally
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `logspecter selftest` still reports full recall and zero false positives
- [ ] I added or updated tests for this change
- [ ] New rules have a positive sample in `src/logspecter/samples.py` (and a negative sample if the format is prone to false positives)
- [ ] Documentation (README / `docs/rules.md`) is updated if behavior or options changed
- [ ] This PR contains **no real credentials or real production log data** (all samples are fake / generated)
