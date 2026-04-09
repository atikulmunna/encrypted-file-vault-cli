"""Service-level tests for hidden-volume foundation behavior."""

from pathlib import Path

import pytest

from vaultcli.container.reader import ContainerReader
from vaultcli.errors import HiddenVolumeError
from vaultcli.vault import VaultService


def test_create_hidden_volume_preserves_public_header_shape(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden.vault"
    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")

    before = ContainerReader.read_path(vault_path).header
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        hidden_size=512,
    )
    after = ContainerReader.read_path(vault_path).header

    assert before.flags == after.flags
    assert before.kdf_profile == after.kdf_profile
    assert after.container_size > before.container_size


def test_create_hidden_volume_cannot_run_twice(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-twice.vault"
    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        hidden_size=512,
    )

    with pytest.raises(HiddenVolumeError):
        VaultService.create_hidden_volume(
            vault_path,
            outer_passphrase="OuterPassphrase123!",
            inner_passphrase="AnotherInnerPassphrase123!",
            hidden_size=512,
        )


def test_outer_add_preserves_hidden_region_bytes(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-preserve.vault"
    first_file = tmp_path / "first.txt"
    second_file = tmp_path / "second.txt"
    first_file.write_text("alpha", encoding="utf-8")
    second_file.write_text("beta", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")
    VaultService.add_paths(vault_path, passphrase="OuterPassphrase123!", sources=[first_file])
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        hidden_size=512,
    )

    before_unlock = VaultService._unlock(vault_path, passphrase="OuterPassphrase123!")
    before_hidden = before_unlock.hidden_region

    VaultService.add_paths(vault_path, passphrase="OuterPassphrase123!", sources=[second_file])

    after_unlock = VaultService._unlock(vault_path, passphrase="OuterPassphrase123!")
    assert after_unlock.hidden_region == before_hidden
    assert len(after_unlock.hidden_region) == len(before_hidden)
