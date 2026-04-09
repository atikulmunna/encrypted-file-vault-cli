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
    result = runner.invoke(app, ["hidden", "create", "--help"])

    assert result.exit_code == 0
    assert "Create a hidden volume." in result.stdout
    assert runner.invoke(app, ["hidden", "list", "--help"]).exit_code == 0
    assert runner.invoke(app, ["hidden", "add", "--help"]).exit_code == 0
    assert runner.invoke(app, ["hidden", "extract", "--help"]).exit_code == 0


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


def test_add_and_extract_commands_round_trip_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "roundtrip.vault"
    source_file = tmp_path / "note.txt"
    source_file.write_text("vault round trip", encoding="utf-8")
    output_dir = tmp_path / "extract"

    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "vault-passphrase"],
    )
    assert create_result.exit_code == 0

    add_result = runner.invoke(
        app,
        [
            "--json",
            "add",
            str(vault_path),
            str(source_file),
            "--passphrase",
            "vault-passphrase",
        ],
    )
    assert add_result.exit_code == 0
    add_payload = json.loads(add_result.stdout)
    assert add_payload["added"][0]["path"] == "note.txt"

    list_result = runner.invoke(
        app,
        ["--json", "list", str(vault_path), "--passphrase", "vault-passphrase"],
    )
    assert list_result.exit_code == 0
    list_payload = json.loads(list_result.stdout)
    assert list_payload["files"][0]["path"] == "note.txt"

    extract_result = runner.invoke(
        app,
        [
            "--json",
            "extract",
            str(vault_path),
            "note.txt",
            "--passphrase",
            "vault-passphrase",
            "--output",
            str(output_dir),
        ],
    )
    assert extract_result.exit_code == 0
    extract_payload = json.loads(extract_result.stdout)
    assert extract_payload["extracted"][0]["path"] == "note.txt"
    assert (output_dir / "note.txt").read_text(encoding="utf-8") == "vault round trip"


def test_extract_all_command_recovers_directory_tree(tmp_path: Path) -> None:
    vault_path = tmp_path / "tree.vault"
    source_dir = tmp_path / "source"
    nested_dir = source_dir / "docs"
    nested_dir.mkdir(parents=True)
    (source_dir / "root.txt").write_text("root", encoding="utf-8")
    (nested_dir / "nested.txt").write_text("nested", encoding="utf-8")
    output_dir = tmp_path / "out"

    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "tree-passphrase"],
    )
    assert create_result.exit_code == 0

    add_result = runner.invoke(
        app,
        [
            "add",
            str(vault_path),
            str(source_dir),
            "--passphrase",
            "tree-passphrase",
        ],
    )
    assert add_result.exit_code == 0

    extract_result = runner.invoke(
        app,
        [
            "extract",
            str(vault_path),
            "--all",
            "--passphrase",
            "tree-passphrase",
            "--output",
            str(output_dir),
        ],
    )
    assert extract_result.exit_code == 0
    assert (output_dir / "source" / "root.txt").read_text(encoding="utf-8") == "root"
    assert (output_dir / "source" / "docs" / "nested.txt").read_text(encoding="utf-8") == "nested"


def test_verify_command_supports_locked_and_unlocked_modes(tmp_path: Path) -> None:
    vault_path = tmp_path / "verify.vault"
    source_file = tmp_path / "secret.txt"
    source_file.write_text("verify me", encoding="utf-8")

    create_result = runner.invoke(app, ["create", str(vault_path), "--passphrase", "verify-pass"])
    assert create_result.exit_code == 0

    add_result = runner.invoke(
        app,
        ["add", str(vault_path), str(source_file), "--passphrase", "verify-pass"],
    )
    assert add_result.exit_code == 0

    locked_result = runner.invoke(app, ["--json", "verify", str(vault_path), "--locked"])
    unlocked_result = runner.invoke(
        app,
        ["--json", "verify", str(vault_path), "--passphrase", "verify-pass"],
    )

    assert locked_result.exit_code == 0
    assert unlocked_result.exit_code == 0

    locked_payload = json.loads(locked_result.stdout)
    unlocked_payload = json.loads(unlocked_result.stdout)

    assert locked_payload["mode"] == "locked"
    assert unlocked_payload["mode"] == "unlocked"
    assert unlocked_payload["active_volume"] == "outer"
    assert unlocked_payload["checked_files"] == 1
    assert unlocked_payload["checked_chunks"] == 1


def test_verify_command_requires_passphrase_without_locked_mode(tmp_path: Path) -> None:
    vault_path = tmp_path / "verify-required.vault"
    create_result = runner.invoke(app, ["create", str(vault_path), "--passphrase", "verify-pass"])
    assert create_result.exit_code == 0

    verify_result = runner.invoke(app, ["verify", str(vault_path)])

    assert verify_result.exit_code != 0
    assert "Pass --passphrase" in verify_result.stderr


def test_rekey_command_updates_vault_passphrase(tmp_path: Path) -> None:
    vault_path = tmp_path / "rekey.vault"
    source_file = tmp_path / "secret.txt"
    source_file.write_text("still there after rekey", encoding="utf-8")

    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "OldPassphrase123!"],
    )
    assert create_result.exit_code == 0

    add_result = runner.invoke(
        app,
        ["add", str(vault_path), str(source_file), "--passphrase", "OldPassphrase123!"],
    )
    assert add_result.exit_code == 0

    rekey_result = runner.invoke(
        app,
        [
            "--json",
            "rekey",
            str(vault_path),
            "--current-passphrase",
            "OldPassphrase123!",
            "--new-passphrase",
            "NewPassphrase123!",
        ],
    )
    assert rekey_result.exit_code == 0
    rekey_payload = json.loads(rekey_result.stdout)
    assert rekey_payload["status"] == "rekeyed"

    old_list_result = runner.invoke(
        app,
        ["list", str(vault_path), "--passphrase", "OldPassphrase123!"],
    )
    assert old_list_result.exit_code != 0

    new_list_result = runner.invoke(
        app,
        ["--json", "list", str(vault_path), "--passphrase", "NewPassphrase123!"],
    )
    assert new_list_result.exit_code == 0
    new_list_payload = json.loads(new_list_result.stdout)
    assert new_list_payload["files"][0]["path"] == "secret.txt"


def test_rekey_command_supports_weak_override(tmp_path: Path) -> None:
    vault_path = tmp_path / "rekey-weak.vault"
    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "OldPassphrase123!"],
    )
    assert create_result.exit_code == 0

    rekey_result = runner.invoke(
        app,
        [
            "--json",
            "rekey",
            str(vault_path),
            "--current-passphrase",
            "OldPassphrase123!",
            "--new-passphrase",
            "weakpass",
            "--allow-weak-passphrase",
        ],
    )
    assert rekey_result.exit_code == 0
    payload = json.loads(rekey_result.stdout)
    assert payload["status"] == "rekeyed"


def test_wipe_command_removes_file(tmp_path: Path) -> None:
    target = tmp_path / "wipe.txt"
    target.write_text("delete me", encoding="utf-8")

    wipe_result = runner.invoke(app, ["--json", "wipe", str(target), "--passes", "2"])

    assert wipe_result.exit_code == 0
    payload = json.loads(wipe_result.stdout)
    assert payload["status"] == "wiped"
    assert payload["passes"] == 2
    assert "SSD and flash storage" in payload["warning"]
    assert not target.exists()


def test_hidden_create_command_reserves_hidden_region(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-cli.vault"
    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "OuterPassphrase123!"],
    )
    assert create_result.exit_code == 0

    hidden_result = runner.invoke(
        app,
        [
            "--json",
            "hidden",
            "create",
            str(vault_path),
            "--hidden-size",
            "512",
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
        ],
    )
    assert hidden_result.exit_code == 0
    payload = json.loads(hidden_result.stdout)
    assert payload["status"] == "created"
    assert payload["hidden_size"] == 512

    info_result = runner.invoke(app, ["--json", "info", str(vault_path)])
    assert info_result.exit_code == 0
    info_payload = json.loads(info_result.stdout)
    assert info_payload["mode"] == "locked"


def test_hidden_add_list_and_extract_commands_round_trip_file(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-roundtrip-cli.vault"
    hidden_source = tmp_path / "inner.txt"
    hidden_source.write_text("hidden cli payload", encoding="utf-8")
    output_dir = tmp_path / "hidden-out"

    create_result = runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "OuterPassphrase123!"],
    )
    assert create_result.exit_code == 0

    hidden_create_result = runner.invoke(
        app,
        [
            "hidden",
            "create",
            str(vault_path),
            "--hidden-size",
            "2048",
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
        ],
    )
    assert hidden_create_result.exit_code == 0

    add_result = runner.invoke(
        app,
        [
            "--json",
            "hidden",
            "add",
            str(vault_path),
            str(hidden_source),
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
        ],
    )
    assert add_result.exit_code == 0
    add_payload = json.loads(add_result.stdout)
    assert add_payload["active_volume"] == "hidden"
    assert add_payload["added"][0]["path"] == "inner.txt"

    list_result = runner.invoke(
        app,
        [
            "--json",
            "hidden",
            "list",
            str(vault_path),
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
        ],
    )
    assert list_result.exit_code == 0
    list_payload = json.loads(list_result.stdout)
    assert list_payload["active_volume"] == "hidden"
    assert list_payload["files"][0]["path"] == "inner.txt"

    extract_result = runner.invoke(
        app,
        [
            "--json",
            "hidden",
            "extract",
            str(vault_path),
            "inner.txt",
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
            "--output",
            str(output_dir),
        ],
    )
    assert extract_result.exit_code == 0
    extract_payload = json.loads(extract_result.stdout)
    assert extract_payload["active_volume"] == "hidden"
    assert extract_payload["extracted"][0]["path"] == "inner.txt"
    assert (output_dir / "inner.txt").read_text(encoding="utf-8") == "hidden cli payload"


def test_hidden_add_does_not_change_outer_cli_listing(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-cli-isolated.vault"
    outer_source = tmp_path / "outer.txt"
    hidden_source = tmp_path / "hidden.txt"
    outer_source.write_text("outer cli file", encoding="utf-8")
    hidden_source.write_text("hidden cli file", encoding="utf-8")

    assert runner.invoke(
        app,
        ["create", str(vault_path), "--passphrase", "OuterPassphrase123!"],
    ).exit_code == 0
    assert runner.invoke(
        app,
        ["add", str(vault_path), str(outer_source), "--passphrase", "OuterPassphrase123!"],
    ).exit_code == 0
    assert runner.invoke(
        app,
        [
            "hidden",
            "create",
            str(vault_path),
            "--hidden-size",
            "2048",
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
        ],
    ).exit_code == 0
    assert runner.invoke(
        app,
        [
            "hidden",
            "add",
            str(vault_path),
            str(hidden_source),
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
        ],
    ).exit_code == 0

    outer_list_result = runner.invoke(
        app,
        ["--json", "list", str(vault_path), "--passphrase", "OuterPassphrase123!"],
    )
    hidden_list_result = runner.invoke(
        app,
        [
            "--json",
            "hidden",
            "list",
            str(vault_path),
            "--outer-passphrase",
            "OuterPassphrase123!",
            "--inner-passphrase",
            "InnerPassphrase123!",
        ],
    )

    assert outer_list_result.exit_code == 0
    assert hidden_list_result.exit_code == 0
    assert json.loads(outer_list_result.stdout)["files"][0]["path"] == "outer.txt"
    assert json.loads(hidden_list_result.stdout)["files"][0]["path"] == "hidden.txt"
