"""Placeholder implementation for `vault extract`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import require_passphrase
from vaultcli.cli.state import AppState
from vaultcli.errors import ContainerFormatError, VaultFileNotFoundError
from vaultcli.vault import VaultService


def extract_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    internal_path: str | None = typer.Argument(
        None,
        help="Internal vault path to extract. Omit it when using --all.",
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Unlock the vault to extract files.",
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
    output_dir: Path = typer.Option(
        Path("."),
        "--output",
        help="Output directory for extracted files.",
    ),
    extract_all: bool = typer.Option(
        False,
        "--all",
        help="Extract every stored file from the outer volume.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Replace existing output files instead of failing safely.",
    ),
) -> None:
    """Unlock the outer volume and extract one path or the full tree."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_passphrase = require_passphrase(
        direct=passphrase,
        env_name=passphrase_env,
        file_path=passphrase_file,
        prompt_text="Vault passphrase",
    )
    try:
        extracted_files = VaultService.extract_files(
            vault_path,
            passphrase=resolved_passphrase,
            output_dir=output_dir,
            internal_path=internal_path,
            extract_all=extract_all,
            overwrite=overwrite,
        )
    except (ContainerFormatError, VaultFileNotFoundError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "vault": str(vault_path),
            "extracted": [
                {
                    "path": item.path,
                    "output_path": str(item.output_path),
                    "original_size": item.original_size,
                }
                for item in extracted_files
            ],
        },
        json_mode=state.json,
    )
