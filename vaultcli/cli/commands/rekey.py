"""Placeholder implementation for `vault rekey`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def rekey_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    current_passphrase: str = typer.Option(
        ...,
        "--current-passphrase",
        help="Current passphrase used to unlock the vault.",
        hide_input=True,
    ),
    new_passphrase: str = typer.Option(
        ...,
        "--new-passphrase",
        help="New passphrase that will protect the same DEK.",
        hide_input=True,
    ),
    allow_weak_passphrase: bool = typer.Option(
        False,
        "--allow-weak-passphrase",
        help="Override the default minimum passphrase policy.",
    ),
) -> None:
    """Rekey an existing vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    updated_path = VaultService.rekey_vault(
        vault_path,
        current_passphrase=current_passphrase,
        new_passphrase=new_passphrase,
        allow_weak_passphrase=allow_weak_passphrase,
    )
    emit(
        {
            "vault": str(updated_path),
            "status": "rekeyed",
        },
        json_mode=state.json,
    )
