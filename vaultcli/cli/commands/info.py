"""Placeholder implementation for `vault info`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def info_command(ctx: typer.Context) -> None:
    """Show vault metadata."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "info", "status": "not_implemented"}, json_mode=state.json)
