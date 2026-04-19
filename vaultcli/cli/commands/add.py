"""Placeholder implementation for `vault add`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import require_passphrase
from vaultcli.cli.state import AppState
from vaultcli.errors import ContainerFormatError, CryptoAuthenticationError
from vaultcli.vault import VaultService


def add_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    sources: list[Path] = typer.Argument(..., help="Source files or directories to add."),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Unlock the vault to add files or directories.",
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
    """Unlock the outer volume and add files or directories.

    Example:
        vault add secrets.vault ./project-files --prompt-passphrase
    """
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_passphrase = require_passphrase(
        direct=passphrase,
        env_name=passphrase_env,
        file_path=passphrase_file,
        prompt_text="Vault passphrase",
    )
    try:
        added_files = VaultService.add_paths(
            vault_path,
            passphrase=resolved_passphrase,
            sources=sources,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create it first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the outer passphrase and try again."
        ) from exc
    except ContainerFormatError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "vault": str(vault_path),
            "added": [
                {"path": item.path, "original_size": item.original_size}
                for item in added_files
            ],
        },
        json_mode=state.json,
    )
