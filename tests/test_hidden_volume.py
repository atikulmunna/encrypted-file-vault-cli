"""Service-level tests for hidden-volume behavior."""

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


def test_hidden_add_list_and_extract_round_trip(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-roundtrip.vault"
    hidden_source = tmp_path / "inner.txt"
    hidden_source.write_text("inside hidden volume", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        hidden_size=2048,
    )

    added = VaultService.add_hidden_paths(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        sources=[hidden_source],
    )
    listed = VaultService.list_hidden_files(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
    )
    extracted = VaultService.extract_hidden_files(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        output_dir=tmp_path / "out",
        internal_path="inner.txt",
    )

    assert added[0].path == "inner.txt"
    assert listed[0].path == "inner.txt"
    assert extracted[0].output_path.read_text(encoding="utf-8") == "inside hidden volume"


def test_hidden_add_does_not_change_outer_file_listing(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-isolated.vault"
    outer_source = tmp_path / "outer.txt"
    hidden_source = tmp_path / "hidden.txt"
    outer_source.write_text("outer file", encoding="utf-8")
    hidden_source.write_text("hidden file", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")
    VaultService.add_paths(vault_path, passphrase="OuterPassphrase123!", sources=[outer_source])
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        hidden_size=2048,
    )

    VaultService.add_hidden_paths(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        sources=[hidden_source],
    )

    outer_files = VaultService.list_files(vault_path, passphrase="OuterPassphrase123!")
    hidden_files = VaultService.list_hidden_files(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
    )

    assert [item.path for item in outer_files] == ["outer.txt"]
    assert [item.path for item in hidden_files] == ["hidden.txt"]


def test_hidden_add_appends_after_existing_hidden_encrypted_data(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-append.vault"
    first_file = tmp_path / "first.txt"
    second_file = tmp_path / "second.txt"
    first_file.write_text("alpha", encoding="utf-8")
    second_file.write_text("beta", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        hidden_size=2048,
    )
    VaultService.add_hidden_paths(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        sources=[first_file],
    )

    before = VaultService._unlock_hidden(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
    )
    first_record = before.hidden.index.files[0]
    prior_hidden_length = len(before.hidden.encrypted_data)

    VaultService.add_hidden_paths(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        sources=[second_file],
    )

    after = VaultService._unlock_hidden(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
    )
    first_after = next(item for item in after.hidden.index.files if item.path == "first.txt")
    second_after = next(item for item in after.hidden.index.files if item.path == "second.txt")

    assert first_after.chunks == first_record.chunks
    assert second_after.chunks[0].offset >= prior_hidden_length


def test_hidden_operations_require_configured_hidden_volume(tmp_path: Path) -> None:
    vault_path = tmp_path / "no-hidden.vault"
    source_file = tmp_path / "note.txt"
    source_file.write_text("no hidden here", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")

    with pytest.raises(HiddenVolumeError):
        VaultService.list_hidden_files(
            vault_path,
            outer_passphrase="OuterPassphrase123!",
            inner_passphrase="InnerPassphrase123!",
        )

    with pytest.raises(HiddenVolumeError):
        VaultService.add_hidden_paths(
            vault_path,
            outer_passphrase="OuterPassphrase123!",
            inner_passphrase="InnerPassphrase123!",
            sources=[source_file],
        )
