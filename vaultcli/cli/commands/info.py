"""Placeholder implementation for `vault info`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import resolve_passphrase
from vaultcli.cli.state import AppState
from vaultcli.errors import ContainerFormatError, CryptoAuthenticationError
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
    prompt_passphrase: bool = typer.Option(
        False,
        "--prompt-passphrase",
        help="Prompt for the vault passphrase and show authenticated metadata.",
    ),
) -> None:
    """Show public metadata, or unlock first for authenticated details."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_passphrase = resolve_passphrase(
        direct=passphrase,
        env_name=passphrase_env,
        file_path=passphrase_file,
        prompt_text="Vault passphrase",
        allow_prompt=prompt_passphrase,
    )
    if resolved_passphrase is None:
        try:
            locked_info = VaultService.read_locked_info(vault_path)
        except FileNotFoundError as exc:
            raise typer.BadParameter(
                f"Vault file not found: {vault_path}. Create it first or check the path."
            ) from exc
        except ContainerFormatError as exc:
            raise typer.BadParameter(str(exc)) from exc
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

    try:
        unlocked_info = VaultService.read_unlocked_info(vault_path, passphrase=resolved_passphrase)
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create it first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the passphrase or run `vault info` without unlocking "
            "to read only public metadata."
        ) from exc
    except ContainerFormatError as exc:
        raise typer.BadParameter(str(exc)) from exc
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
