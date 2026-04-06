"""Placeholder implementation for `vault rekey`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def rekey_command(ctx: typer.Context) -> None:
    """Rekey an existing vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "rekey", "status": "not_implemented"}, json_mode=state.json)
