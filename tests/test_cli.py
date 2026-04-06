"""Tests for the Typer CLI foundation."""

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


def test_json_mode_emits_json_output() -> None:
    result = runner.invoke(app, ["--json", "create"])

    assert result.exit_code == 0
    assert '"command": "create"' in result.stdout
    assert '"status": "not_implemented"' in result.stdout


def test_hidden_subcommand_is_registered() -> None:
    result = runner.invoke(app, ["hidden", "create"])

    assert result.exit_code == 0
    assert "hidden create" in result.stdout
