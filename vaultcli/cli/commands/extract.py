"""Placeholder implementation for `vault extract`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def extract_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    internal_path: str | None = typer.Argument(
        None,
        help="Internal vault path to extract. Omit when using --all.",
    ),
    passphrase: str = typer.Option(
        ...,
        "--passphrase",
        help="Unlock the vault to extract files.",
        hide_input=True,
    ),
    output_dir: Path = typer.Option(
        Path("."),
        "--output",
        help="Output directory for extracted files.",
    ),
    extract_all: bool = typer.Option(False, "--all", help="Extract all files from the active volume."),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing files."),
) -> None:
    """Extract files from a vault."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    extracted_files = VaultService.extract_files(
        vault_path,
        passphrase=passphrase,
        output_dir=output_dir,
        internal_path=internal_path,
        extract_all=extract_all,
        overwrite=overwrite,
    )
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
