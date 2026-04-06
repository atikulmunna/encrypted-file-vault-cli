"""Placeholder implementation for `vault verify`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def verify_command(ctx: typer.Context) -> None:
    """Verify a vault container."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "verify", "status": "not_implemented"}, json_mode=state.json)
