"""Placeholder implementation for `vault add`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def add_command(ctx: typer.Context) -> None:
    """Add files or directories to a vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "add", "status": "not_implemented"}, json_mode=state.json)
