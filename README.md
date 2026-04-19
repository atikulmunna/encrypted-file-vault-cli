# VaultCLI

VaultCLI is a security-focused command-line tool for creating encrypted file vaults in a single portable container.

The project is being built in public with a strong emphasis on auditable cryptography, practical usability, and a clean developer experience. The planned design uses modern authenticated encryption for file content, memory-hard key derivation for passphrases, and an offline-first workflow suitable for developers, privacy-conscious users, and automation environments.

## Quick Start

Install the project locally:

```powershell
python -m poetry install
```

Run the CLI through Poetry during development:

```powershell
python -m poetry run vault --help
```

Create a vault, add a file, inspect it, and extract it again:

```powershell
python -m poetry run vault create demo.vault --passphrase "CorrectHorseBatteryStaple123!"
python -m poetry run vault add demo.vault .\notes.txt --passphrase "CorrectHorseBatteryStaple123!"
python -m poetry run vault list demo.vault --passphrase "CorrectHorseBatteryStaple123!"
python -m poetry run vault extract demo.vault notes.txt --passphrase "CorrectHorseBatteryStaple123!" --output .\restored
```

If you do not want the passphrase to appear in shell history, use one of the safer input paths:

```powershell
python -m poetry run vault create demo.vault
python -m poetry run vault list demo.vault --prompt-passphrase
python -m poetry run vault verify demo.vault --passphrase-env VAULTCLI_PASSPHRASE
```

## Install And Run

Development workflow:

```powershell
python -m poetry install
python -m poetry run vault --help
```

Build distributable artifacts:

```powershell
python -m poetry build
```

After installation, the CLI entrypoint is:

```powershell
vault --help
```

## Common Workflows

Create a vault:

```powershell
python -m poetry run vault create secrets.vault
```

Inspect public metadata without unlocking:

```powershell
python -m poetry run vault info secrets.vault
```

Inspect authenticated metadata after unlocking:

```powershell
python -m poetry run vault info secrets.vault --prompt-passphrase
```

Add a directory tree:

```powershell
python -m poetry run vault add secrets.vault .\project-files --prompt-passphrase
```

Extract everything into a target folder:

```powershell
python -m poetry run vault extract secrets.vault --all --prompt-passphrase --output .\restore
```

Run structural-only verification:

```powershell
python -m poetry run vault verify secrets.vault --locked
```

Run authenticated verification:

```powershell
python -m poetry run vault verify secrets.vault --prompt-passphrase
```

Use environment variables or files for scripted workflows:

```powershell
$env:VAULTCLI_PASSPHRASE = "CorrectHorseBatteryStaple123!"
python -m poetry run vault list secrets.vault --passphrase-env VAULTCLI_PASSPHRASE
python -m poetry run vault rekey secrets.vault --current-passphrase-env VAULTCLI_PASSPHRASE --new-passphrase-file .\new-passphrase.txt
```

## Project Status

VaultCLI is currently in the active hardening and polish stage.

The original implementation backlog has been completed and the repository is now focused on tightening behavior, testing corruption cases, refining the internal API, and improving developer-facing polish. The current public slice includes the core cryptographic services, the container reader/writer, the main CLI workflows, authenticated verification, rekeying, wipe support, hidden-volume management, and metadata-first read paths.

In practice, this means the repository is feature-complete for its current v1 scope but is still being treated as a build-in-public security project rather than a finished release candidate.

Track progress here:
- Issues: https://github.com/atikulmunna/encrypted-file-vault-cli/issues

## Planned Capabilities

- Create encrypted vault containers for files and directories
- Protect file content with authenticated encryption
- Derive keys from passphrases using Argon2id
- Add, list, extract, verify, and rekey vault contents from the CLI
- Support streaming-friendly large-file handling
- Offer secure passphrase input paths for interactive and scripted use
- Explore hidden-volume support for plausible deniability

## Current Commands

- `vault create`
- `vault info`
- `vault list`
- `vault add`
- `vault extract`
- `vault verify`
- `vault rekey`
- `vault wipe`
- `vault hidden create`
- `vault hidden info`
- `vault hidden verify`
- `vault hidden list`
- `vault hidden add`
- `vault hidden extract`

## Development Setup

```powershell
python -m poetry install
python -m poetry run vault --help
.\scripts\smoke-test.ps1
python -m poetry run ruff check .
python -m poetry run mypy vaultcli
python -m poetry run pytest --cov=vaultcli --cov-report=term-missing
python -m poetry build
```

One-command end-to-end smoke test:

```powershell
.\scripts\smoke-test.ps1
```

Keep the temporary vault artifacts for inspection:

```powershell
.\scripts\smoke-test.ps1 -KeepArtifacts
```

The SRS and private working notes are intentionally kept out of git. Public development work is tracked through issues, source, tests, CI, and release notes.

## Design Principles

- Offline first: no network dependency for vault operations
- Auditable cryptography: use well-known primitives from vetted libraries
- Scriptable UX: friendly for shells, automation, and CI pipelines
- Safety over cleverness: explicit failure modes, authenticated metadata, and conservative defaults
- Portability: target Linux, macOS, and Windows

## Security Note

VaultCLI is not production-ready yet. Until the implementation is complete, reviewed, and tested, this repository should be treated as an active build project rather than a finished security product.

If you plan to use this project for real secrets later, please wait for the hardening, review, and broader validation work to be completed first.

See also:
- [Usage Guide](docs/usage.md)
- [Security Status](docs/security-status.md)
- [Threat Model](docs/threat-model.md)
- [Audit Prep](docs/audit-prep.md)

Current caveats:
- Hidden-volume support exists, but plausible-deniability claims should be treated as provisional until the format and threat model receive deeper external review.
- The wipe command is best-effort only and should not be treated as guaranteed secure deletion on SSDs, flash storage, snapshots, or journaling filesystems.
- Python memory handling is improved where practical, but this project does not claim absolute secret zeroization guarantees inside the interpreter.
- This repository currently prioritizes correctness, transparency, and testability over performance tuning for very large real-world datasets.

Suggested evaluation use:
- local experimentation
- code review and security review
- CI and packaging validation
- non-sensitive demo data

Not yet recommended for:
- high-risk secret storage
- production backup of irreplaceable confidential data
- environments that require independently reviewed deniability properties

## Roadmap

The current implementation roadmap is tracked in GitHub Issues, including:

- repository bootstrap and tooling
- KDF and encryption primitives
- container format and reader/writer
- CLI commands
- authenticated verification
- hidden-volume workflows
- CI, packaging, and release hardening

Current post-backlog focus:
- parser and corruption hardening
- larger end-to-end stress coverage
- CLI failure-path polish
- documentation and release-readiness cleanup

Reviewer-facing docs:
- [Usage Guide](docs/usage.md)
- [Security Status](docs/security-status.md)
- [Threat Model](docs/threat-model.md)
- [Audit Prep](docs/audit-prep.md)
- [Code Map](docs/code-map.md)
- [RC Triage](docs/rc-triage.md)
- [RC Status](docs/release-candidate-status.md)
- [Release Checklist](docs/release-checklist.md)

## Repository Scope

This public repository contains implementation work, documentation intended for public consumption, and the issue backlog.

Private design drafts and working specification notes may be maintained locally and are not part of the tracked source tree.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
