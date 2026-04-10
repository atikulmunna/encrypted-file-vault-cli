"""Service-level tests for vault rekey behavior."""

from pathlib import Path

import pytest

from vaultcli.errors import CryptoAuthenticationError, WeakPassphraseError
from vaultcli.vault import VaultService


def test_rekey_changes_passphrase_without_rewriting_encrypted_data(tmp_path: Path) -> None:
    vault_path = tmp_path / "rekey.vault"
    source_file = tmp_path / "secret.txt"
    source_file.write_text("keep ciphertext stable", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="OldPassphrase123!")
    VaultService.add_paths(vault_path, passphrase="OldPassphrase123!", sources=[source_file])

    before = vault_path.read_bytes()
    VaultService.rekey_vault(
        vault_path,
        current_passphrase="OldPassphrase123!",
        new_passphrase="NewPassphrase123!",
    )
    after = vault_path.read_bytes()

    assert before != after
    assert (
        VaultService.list_files(vault_path, passphrase="NewPassphrase123!")[0].path
        == "secret.txt"
    )
    with pytest.raises(CryptoAuthenticationError):
        VaultService.list_files(vault_path, passphrase="OldPassphrase123!")


def test_rekey_rejects_weak_passphrase_without_override(tmp_path: Path) -> None:
    vault_path = tmp_path / "weak-rekey.vault"
    VaultService.create_empty_vault(vault_path, passphrase="OldPassphrase123!")

    with pytest.raises(WeakPassphraseError):
        VaultService.rekey_vault(
            vault_path,
            current_passphrase="OldPassphrase123!",
            new_passphrase="weakpass",
        )


def test_rekey_allows_weak_passphrase_with_override(tmp_path: Path) -> None:
    vault_path = tmp_path / "weak-override.vault"
    VaultService.create_empty_vault(vault_path, passphrase="OldPassphrase123!")

    VaultService.rekey_vault(
        vault_path,
        current_passphrase="OldPassphrase123!",
        new_passphrase="weakpass",
        allow_weak_passphrase=True,
    )

    info = VaultService.read_unlocked_info(vault_path, passphrase="weakpass")
    assert info.active_volume == "outer"
