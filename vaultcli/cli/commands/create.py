"""Placeholder implementation for `vault create`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import require_passphrase
from vaultcli.cli.state import AppState
from vaultcli.crypto.kdf import KdfProfileName
from vaultcli.vault import VaultService


def create_command(
    ctx: typer.Context,
    output_path: Path,
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Passphrase used to derive the vault KEK.",
        hide_input=True,
    ),
    passphrase_env: str | None = typer.Option(
        None,
        "--passphrase-env",
        help="Environment variable containing the vault passphrase.",
    ),
    passphrase_file: Path | None = typer.Option(
        None,
        "--passphrase-file",
        help="Path to a UTF-8 text file containing the vault passphrase.",
    ),
    kdf_profile: KdfProfileName = typer.Option(
        KdfProfileName.INTERACTIVE,
        "--kdf-profile",
        help="Named Argon2id profile for the outer volume.",
        case_sensitive=False,
    ),
) -> None:
    """Create a new outer vault and prompt for a passphrase if needed."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_passphrase = require_passphrase(
        direct=passphrase,
        env_name=passphrase_env,
        file_path=passphrase_file,
        prompt_text="Vault passphrase",
        confirm=True,
    )
    created_path = VaultService.create_empty_vault(
        output_path,
        passphrase=resolved_passphrase,
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
