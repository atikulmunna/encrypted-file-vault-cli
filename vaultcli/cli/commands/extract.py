"""Placeholder implementation for `vault extract`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def extract_command(ctx: typer.Context) -> None:
    """Extract files from a vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "extract", "status": "not_implemented"}, json_mode=state.json)
