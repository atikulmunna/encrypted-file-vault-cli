"""Placeholder implementation for `vault hidden` commands."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


app = typer.Typer(help="Manage hidden-volume operations.", add_completion=False)


@app.command("create")
def hidden_create_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    hidden_size: int = typer.Option(..., "--hidden-size", help="Size of the hidden tail region in bytes."),
    outer_passphrase: str = typer.Option(
        ...,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    inner_passphrase: str = typer.Option(
        ...,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    allow_weak_passphrase: bool = typer.Option(
        False,
        "--allow-weak-passphrase",
        help="Override the default minimum passphrase policy for the hidden passphrase.",
    ),
) -> None:
    """Create a hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    created_path = VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase=outer_passphrase,
        inner_passphrase=inner_passphrase,
        hidden_size=hidden_size,
        allow_weak_passphrase=allow_weak_passphrase,
    )
    emit(
        {
            "command": "hidden create",
            "status": "created",
            "vault": str(created_path),
            "hidden_size": hidden_size,
        },
        json_mode=state.json,
    )
