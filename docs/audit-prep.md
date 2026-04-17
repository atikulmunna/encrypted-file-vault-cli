# Audit Prep

This document is meant to help an external reviewer or security-minded contributor approach the repository efficiently.

## Recommended Reading Order

1. [README.md](../README.md)
2. [docs/security-status.md](security-status.md)
3. [docs/threat-model.md](threat-model.md)
4. [docs/release-checklist.md](release-checklist.md)

Then move into the implementation:

1. `vaultcli/crypto/`
2. `vaultcli/container/`
3. `vaultcli/vault/`
4. `vaultcli/cli/`
5. `tests/`

## Areas Worth Special Attention

- key derivation and DEK wrapping
- authenticated index encoding and decoding
- chunk offset accounting during add and extract flows
- outer versus hidden-volume boundary handling
- hidden reserved-tail preservation during updates
- parser behavior under malformed or truncated inputs
- passphrase input handling in scripted and interactive modes

## Questions Reviewers Should Be Able To Answer

- does any user-facing workflow write plaintext temp files unexpectedly?
- are file chunks and encrypted indexes always authenticated before trust?
- do offset calculations stay coherent when appending new outer or hidden data?
- does a failed parse or failed authentication stop processing cleanly?
- are hidden-volume claims and caveats stated conservatively enough?
- are there places where Python runtime behavior weakens intended guarantees?

## Practical Review Commands

```powershell
python -m poetry run ruff check .
python -m poetry run mypy vaultcli
python -m poetry run pytest -q
python -m poetry run pytest --cov=vaultcli --cov-report=term-missing
python -m poetry build
```

## Current Reviewer Caveats

- this repository is still pre-release
- hidden-volume deniability should be reviewed with extra skepticism
- wipe behavior should be treated as best-effort only
- performance tuning is not the main optimization target yet

## Good Review Outcomes

A useful review at the current stage would ideally produce:

- confirmed invariants that already look sound
- concrete bug reports or ambiguity reports
- threat-model gaps
- documentation corrections where the code and the stated guarantees drift apart
