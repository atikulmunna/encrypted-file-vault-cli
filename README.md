# VaultCLI

VaultCLI is a security-focused command-line tool for creating encrypted file vaults in a single portable container.

The project is being built in public with a strong emphasis on auditable cryptography, practical usability, and a clean developer experience. The planned design uses modern authenticated encryption for file content, memory-hard key derivation for passphrases, and an offline-first workflow suitable for developers, privacy-conscious users, and automation environments.

## Project Status

VaultCLI is currently in the active hardening and polish stage.

The original implementation backlog has been completed and the repository is now focused on tightening behavior, testing corruption cases, refining the internal API, and improving developer-facing polish. The current public slice includes the core cryptographic services, the container reader/writer, the main CLI workflows, authenticated verification, rekeying, wipe support, hidden-volume management, and metadata-first read paths.

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
python -m poetry run ruff check .
python -m poetry run mypy vaultcli
python -m poetry run pytest --cov=vaultcli --cov-report=term-missing
python -m poetry build
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

## Roadmap

The current implementation roadmap is tracked in GitHub Issues, including:

- repository bootstrap and tooling
- KDF and encryption primitives
- container format and reader/writer
- CLI commands
- authenticated verification
- hidden-volume workflows
- CI, packaging, and release hardening

## Repository Scope

This public repository contains implementation work, documentation intended for public consumption, and the issue backlog.

Private design drafts and working specification notes may be maintained locally and are not part of the tracked source tree.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
