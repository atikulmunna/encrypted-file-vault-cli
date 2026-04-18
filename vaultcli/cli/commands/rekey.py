"""Placeholder implementation for `vault rekey`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import require_named_passphrase
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def rekey_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    current_passphrase: str | None = typer.Option(
        None,
        "--current-passphrase",
        help="Current passphrase used to unlock the vault.",
        hide_input=True,
    ),
    current_passphrase_env: str | None = typer.Option(
        None,
        "--current-passphrase-env",
        help="Environment variable containing the current vault passphrase.",
    ),
    current_passphrase_file: Path | None = typer.Option(
        None,
        "--current-passphrase-file",
        help="Path to a UTF-8 text file containing the current vault passphrase.",
    ),
    new_passphrase: str | None = typer.Option(
        None,
        "--new-passphrase",
        help="New passphrase that will protect the same DEK.",
        hide_input=True,
    ),
    new_passphrase_env: str | None = typer.Option(
        None,
        "--new-passphrase-env",
        help="Environment variable containing the new vault passphrase.",
    ),
    new_passphrase_file: Path | None = typer.Option(
        None,
        "--new-passphrase-file",
        help="Path to a UTF-8 text file containing the new vault passphrase.",
    ),
    allow_weak_passphrase: bool = typer.Option(
        False,
        "--allow-weak-passphrase",
        help="Override the default minimum passphrase policy.",
    ),
) -> None:
    """Change the outer passphrase without re-encrypting stored file data."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_current_passphrase = require_named_passphrase(
        option_name="current-passphrase",
        direct=current_passphrase,
        env_name=current_passphrase_env,
        file_path=current_passphrase_file,
        prompt_text="Current vault passphrase",
    )
    resolved_new_passphrase = require_named_passphrase(
        option_name="new-passphrase",
        direct=new_passphrase,
        env_name=new_passphrase_env,
        file_path=new_passphrase_file,
        prompt_text="New vault passphrase",
        confirm=True,
    )
    updated_path = VaultService.rekey_vault(
        vault_path,
        current_passphrase=resolved_current_passphrase,
        new_passphrase=resolved_new_passphrase,
        allow_weak_passphrase=allow_weak_passphrase,
    )
    emit(
        {
            "vault": str(updated_path),
            "status": "rekeyed",
        },
        json_mode=state.json,
    )
