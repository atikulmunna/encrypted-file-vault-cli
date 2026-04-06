"""Placeholder implementation for `vault verify`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def verify_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Unlock the vault to verify authenticated contents.",
        hide_input=True,
    ),
    locked: bool = typer.Option(
        False,
        "--locked",
        help="Run structural-only verification without authenticating ciphertext.",
    ),
) -> None:
    """Verify a vault container."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    if locked:
        result = VaultService.verify_locked(vault_path)
    else:
        if passphrase is None:
            typer.echo(
                "Pass --passphrase for authenticated verification or use --locked.",
                err=True,
            )
            raise typer.Exit(code=2)
        result = VaultService.verify_unlocked(vault_path, passphrase=passphrase)

    emit(
        {
            "vault": str(vault_path),
            "mode": result.mode,
            "active_volume": result.active_volume,
            "status": result.status,
            "checked_files": result.checked_files,
            "checked_chunks": result.checked_chunks,
        },
        json_mode=state.json,
    )
