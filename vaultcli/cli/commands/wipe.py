"""Placeholder implementation for `vault wipe`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.wipe import wipe_file


def wipe_command(
    ctx: typer.Context,
    paths: list[Path] = typer.Argument(..., help="One or more plaintext files to wipe."),
    passes: int = typer.Option(3, "--passes", help="Number of overwrite passes before deletion."),
) -> None:
    """Best-effort overwrite and delete plaintext files."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    wiped_paths = [str(wipe_file(path, passes=passes)) for path in paths]
    emit(
        {
            "status": "wiped",
            "paths": wiped_paths,
            "passes": passes,
            "warning": "Best-effort only; SSD and flash storage may retain recoverable data.",
        },
        json_mode=state.json,
    )
