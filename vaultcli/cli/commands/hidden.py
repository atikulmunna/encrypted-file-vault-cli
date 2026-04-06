"""Placeholder implementation for `vault hidden` commands."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


app = typer.Typer(help="Manage hidden-volume operations.", add_completion=False)


@app.command("create")
def hidden_create_command(ctx: typer.Context) -> None:
    """Create a hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit(
        {"command": "hidden create", "status": "not_implemented"},
        json_mode=state.json,
    )
