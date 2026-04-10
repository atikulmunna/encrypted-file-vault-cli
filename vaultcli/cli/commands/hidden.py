"""Implementation for `vault hidden` commands."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService

app = typer.Typer(help="Manage hidden-volume operations.", add_completion=False)


@app.command("create")
def hidden_create_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    hidden_size: int = typer.Option(
        ...,
        "--hidden-size",
        help="Size of the hidden tail region in bytes.",
    ),
    outer_passphrase: str = typer.Option(
        ...,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    inner_passphrase: str = typer.Option(
        ...,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    allow_weak_passphrase: bool = typer.Option(
        False,
        "--allow-weak-passphrase",
        help="Override the default minimum passphrase policy for the hidden passphrase.",
    ),
) -> None:
    """Create a hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    created_path = VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase=outer_passphrase,
        inner_passphrase=inner_passphrase,
        hidden_size=hidden_size,
        allow_weak_passphrase=allow_weak_passphrase,
    )
    emit(
        {
            "command": "hidden create",
            "status": "created",
            "vault": str(created_path),
            "hidden_size": hidden_size,
        },
        json_mode=state.json,
    )


@app.command("list")
def hidden_list_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    outer_passphrase: str = typer.Option(
        ...,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    inner_passphrase: str = typer.Option(
        ...,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
) -> None:
    """List authenticated contents of the hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    files = VaultService.list_hidden_files(
        vault_path,
        outer_passphrase=outer_passphrase,
        inner_passphrase=inner_passphrase,
    )
    emit(
        {
            "vault": str(vault_path),
            "active_volume": "hidden",
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


@app.command("add")
def hidden_add_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    sources: list[Path] = typer.Argument(..., help="Source files or directories to add."),
    outer_passphrase: str = typer.Option(
        ...,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    inner_passphrase: str = typer.Option(
        ...,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
) -> None:
    """Add files or directories to the hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    added_files = VaultService.add_hidden_paths(
        vault_path,
        outer_passphrase=outer_passphrase,
        inner_passphrase=inner_passphrase,
        sources=sources,
    )
    emit(
        {
            "vault": str(vault_path),
            "active_volume": "hidden",
            "added": [
                {"path": item.path, "original_size": item.original_size}
                for item in added_files
            ],
        },
        json_mode=state.json,
    )


@app.command("extract")
def hidden_extract_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    internal_path: str | None = typer.Argument(
        None,
        help="Internal hidden-volume path to extract. Omit when using --all.",
    ),
    outer_passphrase: str = typer.Option(
        ...,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    inner_passphrase: str = typer.Option(
        ...,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    output_dir: Path = typer.Option(
        Path("."),
        "--output",
        help="Output directory for extracted files.",
    ),
    extract_all: bool = typer.Option(
        False,
        "--all",
        help="Extract all files from the hidden volume.",
    ),
    overwrite: bool = typer.Option(False, "--overwrite", help="Overwrite existing files."),
) -> None:
    """Extract files from the hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    extracted_files = VaultService.extract_hidden_files(
        vault_path,
        outer_passphrase=outer_passphrase,
        inner_passphrase=inner_passphrase,
        output_dir=output_dir,
        internal_path=internal_path,
        extract_all=extract_all,
        overwrite=overwrite,
    )
    emit(
        {
            "vault": str(vault_path),
            "active_volume": "hidden",
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
