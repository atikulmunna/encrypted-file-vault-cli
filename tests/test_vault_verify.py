"""Service-level tests for vault verification workflows."""

from pathlib import Path

import pytest

from vaultcli.errors import ContainerFormatError, CryptoAuthenticationError
from vaultcli.vault import VaultService


def test_verify_unlocked_succeeds_for_valid_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "verify.vault"
    source_file = tmp_path / "note.txt"
    source_file.write_text("verify me", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="verify-pass")
    VaultService.add_paths(vault_path, passphrase="verify-pass", sources=[source_file])

    result = VaultService.verify_unlocked(vault_path, passphrase="verify-pass")

    assert result.mode == "unlocked"
    assert result.active_volume == "outer"
    assert result.status == "verified"
    assert result.checked_files == 1
    assert result.checked_chunks == 1


def test_verify_unlocked_counts_multiple_chunks_for_large_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "verify-large.vault"
    source_file = tmp_path / "large.bin"
    source_file.write_bytes((b"verify-chunk-" * 90_000) + b"tail")

    VaultService.create_empty_vault(vault_path, passphrase="verify-pass")
    VaultService.add_paths(vault_path, passphrase="verify-pass", sources=[source_file])

    result = VaultService.verify_unlocked(vault_path, passphrase="verify-pass")

    assert result.mode == "unlocked"
    assert result.active_volume == "outer"
    assert result.status == "verified"
    assert result.checked_files == 1
    assert result.checked_chunks > 1


def test_verify_locked_succeeds_for_valid_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "locked-verify.vault"

    VaultService.create_empty_vault(vault_path, passphrase="verify-pass")
    result = VaultService.verify_locked(vault_path)

    assert result.mode == "locked"
    assert result.status == "verified"


def test_verify_unlocked_detects_tampered_encrypted_data(tmp_path: Path) -> None:
    vault_path = tmp_path / "tampered.vault"
    source_file = tmp_path / "secret.txt"
    source_file.write_text("tamper target", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="verify-pass")
    VaultService.add_paths(vault_path, passphrase="verify-pass", sources=[source_file])

    payload = bytearray(vault_path.read_bytes())
    payload[-1] ^= 0x01
    vault_path.write_bytes(bytes(payload))

    with pytest.raises((CryptoAuthenticationError, ContainerFormatError)):
        VaultService.verify_unlocked(vault_path, passphrase="verify-pass")


def test_verify_locked_rejects_truncated_container(tmp_path: Path) -> None:
    vault_path = tmp_path / "truncated.vault"
    VaultService.create_empty_vault(vault_path, passphrase="verify-pass")
    payload = vault_path.read_bytes()[:-8]
    vault_path.write_bytes(payload)

    with pytest.raises(ContainerFormatError):
        VaultService.verify_locked(vault_path)
