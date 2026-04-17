"""Platform-oriented behavior checks for path and file handling."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vaultcli.cli.main import app
from vaultcli.vault import VaultService
from vaultcli.wipe import wipe_file

runner = CliRunner()


def test_outer_directory_add_normalizes_internal_paths_to_forward_slashes(tmp_path: Path) -> None:
    vault_path = tmp_path / "outer-platform.vault"
    source_root = tmp_path / "source"
    nested_dir = source_root / "docs" / "deep"
    nested_dir.mkdir(parents=True)
    (source_root / "root.txt").write_text("root", encoding="utf-8")
    (nested_dir / "note.txt").write_text("nested", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="PlatformPassphrase123!")
    VaultService.add_paths(
        vault_path,
        passphrase="PlatformPassphrase123!",
        sources=[source_root],
    )

    listed = VaultService.list_files(vault_path, passphrase="PlatformPassphrase123!")

    assert [item.path for item in listed] == ["source/docs/deep/note.txt", "source/root.txt"]
    assert all("\\" not in item.path for item in listed)


def test_hidden_directory_add_normalizes_internal_paths_to_forward_slashes(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-platform.vault"
    source_root = tmp_path / "hidden-source"
    nested_dir = source_root / "docs" / "deep"
    nested_dir.mkdir(parents=True)
    (source_root / "root.txt").write_text("root", encoding="utf-8")
    (nested_dir / "note.txt").write_text("nested", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="OuterPlatformPass123!")
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPlatformPass123!",
        inner_passphrase="InnerPlatformPass123!",
        hidden_size=2048,
    )
    VaultService.add_hidden_paths(
        vault_path,
        outer_passphrase="OuterPlatformPass123!",
        inner_passphrase="InnerPlatformPass123!",
        sources=[source_root],
    )

    listed = VaultService.list_hidden_files(
        vault_path,
        outer_passphrase="OuterPlatformPass123!",
        inner_passphrase="InnerPlatformPass123!",
    )

    assert [item.path for item in listed] == [
        "hidden-source/docs/deep/note.txt",
        "hidden-source/root.txt",
    ]
    assert all("\\" not in item.path for item in listed)


def test_cli_passphrase_file_accepts_crlf_line_endings(tmp_path: Path) -> None:
    vault_path = tmp_path / "crlf.vault"
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_bytes(b"CrLfPassphrase123!\r\n")

    create_result = runner.invoke(
        app,
        [
            "create",
            str(vault_path),
            "--passphrase-file",
            str(passphrase_file),
        ],
    )
    list_result = runner.invoke(
        app,
        [
            "--json",
            "list",
            str(vault_path),
            "--passphrase-file",
            str(passphrase_file),
        ],
    )

    assert create_result.exit_code == 0
    assert list_result.exit_code == 0


def test_wipe_file_removes_zero_length_file(tmp_path: Path) -> None:
    target = tmp_path / "empty.txt"
    target.write_bytes(b"")

    wiped = wipe_file(target, passes=2)

    assert wiped == target
    assert not target.exists()
