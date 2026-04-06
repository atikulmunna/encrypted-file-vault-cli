"""Placeholder implementation for `vault list`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def list_command(ctx: typer.Context) -> None:
    """List authenticated contents of a vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "list", "status": "not_implemented"}, json_mode=state.json)
