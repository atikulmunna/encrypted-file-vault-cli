"""Placeholder implementation for `vault info`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def info_command(
    ctx: typer.Context,
    vault_path: Path,
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Unlock the vault to read authenticated metadata.",
        hide_input=True,
    ),
) -> None:
    """Show vault metadata."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    if passphrase is None:
        locked_info = VaultService.read_locked_info(vault_path)
        emit(
            {
                "vault": str(locked_info.path),
                "mode": "locked",
                "format": f"v{locked_info.format_version}",
                "kdf_profile": locked_info.kdf_profile.value,
                "container_size": locked_info.container_size,
            },
            json_mode=state.json,
        )
        return

    unlocked_info = VaultService.read_unlocked_info(vault_path, passphrase=passphrase)
    emit(
        {
            "vault": str(unlocked_info.path),
            "mode": "unlocked",
            "active_volume": unlocked_info.active_volume,
            "format": f"v{unlocked_info.format_version}",
            "kdf_profile": unlocked_info.kdf_profile.value,
            "created_at": unlocked_info.created_at,
            "files": unlocked_info.file_count,
            "encrypted_size": unlocked_info.encrypted_size,
        },
        json_mode=state.json,
    )
