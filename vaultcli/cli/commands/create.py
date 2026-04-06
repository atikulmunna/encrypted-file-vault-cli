"""Placeholder implementation for `vault create`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.crypto.kdf import KdfProfileName
from vaultcli.vault import VaultService


def create_command(
    ctx: typer.Context,
    output_path: Path,
    passphrase: str = typer.Option(
        ...,
        "--passphrase",
        help="Passphrase used to derive the vault KEK.",
        hide_input=True,
    ),
    kdf_profile: KdfProfileName = typer.Option(
        KdfProfileName.INTERACTIVE,
        "--kdf-profile",
        help="Named Argon2id profile for the outer volume.",
        case_sensitive=False,
    ),
) -> None:
    """Create a new vault container."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    created_path = VaultService.create_empty_vault(
        output_path,
        passphrase=passphrase,
        kdf_profile=kdf_profile,
    )
    emit(
        {
            "command": "create",
            "status": "created",
            "path": str(created_path),
            "kdf_profile": kdf_profile.value,
        },
        json_mode=state.json,
    )
