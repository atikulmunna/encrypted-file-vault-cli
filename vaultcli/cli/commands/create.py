"""Placeholder implementation for `vault create`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def create_command(ctx: typer.Context) -> None:
    """Create a new vault container."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "create", "status": "not_implemented"}, json_mode=state.json)
