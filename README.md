# VaultCLI

VaultCLI is a security-focused command-line tool for creating encrypted file vaults in a single portable container.

The project is being built in public with a strong emphasis on auditable cryptography, practical usability, and a clean developer experience. The planned design uses modern authenticated encryption for file content, memory-hard key derivation for passphrases, and an offline-first workflow suitable for developers, privacy-conscious users, and automation environments.

## Project Status

VaultCLI is currently in the early implementation stage.

The repository is being set up issue by issue, starting from project scaffolding and moving toward the core cryptographic engine, container format, CLI workflows, integrity verification, and hidden-volume support.

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

## Design Principles

- Offline first: no network dependency for vault operations
- Auditable cryptography: use well-known primitives from vetted libraries
- Scriptable UX: friendly for shells, automation, and CI pipelines
- Safety over cleverness: explicit failure modes, authenticated metadata, and conservative defaults
- Portability: target Linux, macOS, and Windows

## Security Note

VaultCLI is not production-ready yet. Until the implementation is complete, reviewed, and tested, this repository should be treated as an active build project rather than a finished security product.

If you plan to use this project for real secrets later, please wait for the hardening, testing, and review milestones to be completed first.

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

License to be added during the initial project setup.
