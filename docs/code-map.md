# Code Map

This is a quick orientation guide for reviewers and contributors.

## Top-Level Areas

- `vaultcli/crypto/`
  Primitive wrappers and key-derivation helpers.

- `vaultcli/container/`
  Public header handling, encrypted index serialization, container reading, and container writing.

- `vaultcli/vault/`
  Higher-level vault orchestration:
  - shared service models
  - ciphertext source helpers
  - hidden-volume region helpers
  - outer and hidden workflow coordination

- `vaultcli/cli/`
  Typer application wiring, passphrase-input helpers, and command implementations.

- `tests/`
  Behavioral, hardening, CLI, stress, and platform-oriented coverage.

## Suggested Review Path

1. `vaultcli/crypto/kdf.py`
2. `vaultcli/crypto/aes_gcm.py`
3. `vaultcli/container/format.py`
4. `vaultcli/container/index.py`
5. `vaultcli/container/reader.py`
6. `vaultcli/container/writer.py`
7. `vaultcli/vault/hidden.py`
8. `vaultcli/vault/ciphertext.py`
9. `vaultcli/vault/models.py`
10. `vaultcli/vault/vault.py`
11. `vaultcli/cli/`
12. `tests/`

## Test Groups

- `tests/test_container_io.py`
  Container parser and writer behavior.

- `tests/test_container_hardening.py`
  Structural corruption and hidden-region corruption handling.

- `tests/test_index_hardening.py`
  Volume-index mutation and decoder robustness.

- `tests/test_vault_service.py`
  Outer-volume workflow behavior.

- `tests/test_hidden_volume.py`
  Hidden-volume workflow behavior.

- `tests/test_vault_verify.py`
  Verification behavior.

- `tests/test_stress_e2e.py`
  Larger realistic workflow coverage.

- `tests/test_platform_behavior.py`
  Cross-platform path and file-handling expectations.

- `tests/test_cli.py`
  Command-line interface behavior and failure paths.
