"""Tests for the Typer CLI foundation."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vaultcli import __version__
from vaultcli.cli.main import app


runner = CliRunner()


def test_root_help_shows_expected_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "create" in result.stdout
    assert "verify" in result.stdout
    assert "hidden" in result.stdout


def test_version_flag_shows_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_create_command_creates_vault_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "sample.vault"
    result = runner.invoke(
        app,
        ["--json", "create", str(vault_path), "--passphrase", "correct horse battery staple"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "create"
    assert payload["status"] == "created"
    assert vault_path.exists()


def test_hidden_subcommand_is_registered() -> None:
    result = runner.invoke(app, ["hidden", "create"])

    assert result.exit_code == 0
    assert "hidden create" in result.stdout


def test_info_command_supports_locked_and_unlocked_modes(tmp_path: Path) -> None:
    vault_path = tmp_path / "info.vault"
    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "vault-passphrase"],
    )
    assert create_result.exit_code == 0

    locked_result = runner.invoke(app, ["--json", "info", str(vault_path)])
    unlocked_result = runner.invoke(
        app,
        ["--json", "info", str(vault_path), "--passphrase", "vault-passphrase"],
    )

    assert locked_result.exit_code == 0
    assert unlocked_result.exit_code == 0

    locked_payload = json.loads(locked_result.stdout)
    unlocked_payload = json.loads(unlocked_result.stdout)

    assert locked_payload["mode"] == "locked"
    assert unlocked_payload["mode"] == "unlocked"
    assert unlocked_payload["files"] == 0
    assert unlocked_payload["active_volume"] == "outer"


def test_list_command_returns_empty_file_list_for_new_vault(tmp_path: Path) -> None:
    vault_path = tmp_path / "list.vault"
    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "vault-passphrase"],
    )
    assert create_result.exit_code == 0

    list_result = runner.invoke(
        app,
        ["--json", "list", str(vault_path), "--passphrase", "vault-passphrase"],
    )

    assert list_result.exit_code == 0
    payload = json.loads(list_result.stdout)
    assert payload["active_volume"] == "outer"
    assert payload["files"] == []
