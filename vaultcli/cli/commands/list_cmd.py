"""Placeholder implementation for `vault list`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def list_command(
    ctx: typer.Context,
    vault_path: Path,
    passphrase: str = typer.Option(
        ...,
        "--passphrase",
        help="Unlock the vault to list authenticated entries.",
        hide_input=True,
    ),
) -> None:
    """List authenticated contents of a vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    files = VaultService.list_files(vault_path, passphrase=passphrase)
    emit(
        {
            "vault": str(vault_path),
            "active_volume": "outer",
            "files": [
                {
                    "path": file.path,
                    "original_size": file.original_size,
                    "added_at": file.added_at,
                }
                for file in files
            ],
        },
        json_mode=state.json,
    )
