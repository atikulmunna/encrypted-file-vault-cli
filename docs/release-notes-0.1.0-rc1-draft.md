# Draft Release Notes: 0.1.0-rc1

## Summary

This draft release candidate packages the first feature-complete engineering slice of VaultCLI. It includes the core encrypted-container workflows, hidden-volume support, authenticated verification, metadata-first read paths, and a substantially stronger hardening and documentation baseline than the original implementation backlog.

## Highlights

- outer-volume create, info, list, add, extract, verify, and rekey workflows
- hidden-volume create, info, verify, list, add, and extract workflows
- chunked file encryption and extraction paths
- atomic container writes and metadata-first container reads
- best-effort wipe command with explicit storage caveats
- CI, packaging, release workflows, and reviewer-facing documentation

## Hardening Improvements

- malformed container and hidden-region corruption coverage
- deterministic parser mutation coverage for container and index decoding
- CLI failure-path coverage for conflicting and missing passphrase sources
- larger end-to-end stress tests across directory trees and mixed outer/hidden use
- platform-oriented tests for path normalization and CRLF passphrase files

## Security Notes

- VaultCLI is still pre-release software.
- Hidden-volume deniability claims should still be treated as provisional.
- The wipe command is best-effort only and should not be interpreted as guaranteed secure deletion.
- Python runtime behavior still limits any claim of complete in-memory secret eradication.

## Testing

The current release-prep workflow expects:

- `python -m poetry run ruff check .`
- `python -m poetry run mypy vaultcli`
- `python -m poetry run pytest --cov=vaultcli --cov-report=term-missing`
- `python -m poetry build`

## Known Limits

- no external audit or security review has been completed yet
- more adversarial fuzzing and broader long-running stress coverage would still strengthen confidence
- hidden-volume security properties need more review before making stronger claims

## Compatibility Notes

- the project currently targets Python 3.11+
- the CLI surface is still pre-1.0 and may change before a stable release
