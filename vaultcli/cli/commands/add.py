"""Placeholder implementation for `vault add`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def add_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    sources: list[Path] = typer.Argument(..., help="Source files or directories to add."),
    passphrase: str = typer.Option(
        ...,
        "--passphrase",
        help="Unlock the vault to add files or directories.",
        hide_input=True,
    ),
) -> None:
    """Add files or directories to a vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    added_files = VaultService.add_paths(
        vault_path,
        passphrase=passphrase,
        sources=sources,
    )
    emit(
        {
            "vault": str(vault_path),
            "added": [
                {"path": item.path, "original_size": item.original_size}
                for item in added_files
            ],
        },
        json_mode=state.json,
    )
