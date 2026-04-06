"""Placeholder implementation for `vault wipe`."""

from __future__ import annotations

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState


def wipe_command(ctx: typer.Context) -> None:
    """Securely wipe plaintext files."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    emit({"command": "wipe", "status": "not_implemented"}, json_mode=state.json)
