"""Placeholder implementation for `vault list`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import require_passphrase
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def list_command(
    ctx: typer.Context,
    vault_path: Path,
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Unlock the vault to list authenticated entries.",
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
) -> None:
    """Unlock the outer volume and list authenticated file entries."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_passphrase = require_passphrase(
        direct=passphrase,
        env_name=passphrase_env,
        file_path=passphrase_file,
        prompt_text="Vault passphrase",
    )
    files = VaultService.list_files(vault_path, passphrase=resolved_passphrase)
    emit(
        {
            "vault": str(vault_path),
            "active_volume": "outer",
            "files": [
                {
                    "path": file.path,
                    "original_size": file.original_size,
                    "added_at": file.added_at,
                }
                for file in files
            ],
        },
        json_mode=state.json,
    )
