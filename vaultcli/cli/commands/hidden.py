"""Implementation for `vault hidden` commands."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import require_named_passphrase
from vaultcli.cli.state import AppState
from vaultcli.errors import (
    ContainerFormatError,
    CryptoAuthenticationError,
    HiddenVolumeError,
    VaultFileNotFoundError,
    WeakPassphraseError,
)
from vaultcli.vault import VaultService

app = typer.Typer(
    help=(
        "Manage hidden-volume operations that require both the outer and inner passphrases."
    ),
    add_completion=False,
)


@app.command("create")
def hidden_create_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    hidden_size: int = typer.Option(
        ...,
        "--hidden-size",
        help="Size of the hidden tail region in bytes.",
    ),
    outer_passphrase: str | None = typer.Option(
        None,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    outer_passphrase_env: str | None = typer.Option(
        None,
        "--outer-passphrase-env",
        help="Environment variable containing the outer-volume passphrase.",
    ),
    outer_passphrase_file: Path | None = typer.Option(
        None,
        "--outer-passphrase-file",
        help="Path to a UTF-8 text file containing the outer-volume passphrase.",
    ),
    inner_passphrase: str | None = typer.Option(
        None,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    inner_passphrase_env: str | None = typer.Option(
        None,
        "--inner-passphrase-env",
        help="Environment variable containing the hidden-volume passphrase.",
    ),
    inner_passphrase_file: Path | None = typer.Option(
        None,
        "--inner-passphrase-file",
        help="Path to a UTF-8 text file containing the hidden-volume passphrase.",
    ),
    allow_weak_passphrase: bool = typer.Option(
        False,
        "--allow-weak-passphrase",
        help="Override the default minimum passphrase policy for the hidden passphrase.",
    ),
) -> None:
    """Create a hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_outer_passphrase = require_named_passphrase(
        option_name="outer-passphrase",
        direct=outer_passphrase,
        env_name=outer_passphrase_env,
        file_path=outer_passphrase_file,
        prompt_text="Outer vault passphrase",
    )
    resolved_inner_passphrase = require_named_passphrase(
        option_name="inner-passphrase",
        direct=inner_passphrase,
        env_name=inner_passphrase_env,
        file_path=inner_passphrase_file,
        prompt_text="Hidden volume passphrase",
        confirm=True,
    )
    try:
        created_path = VaultService.create_hidden_volume(
            vault_path,
            outer_passphrase=resolved_outer_passphrase,
            inner_passphrase=resolved_inner_passphrase,
            hidden_size=hidden_size,
            allow_weak_passphrase=allow_weak_passphrase,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create the outer vault first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the outer passphrase and try again."
        ) from exc
    except WeakPassphraseError as exc:
        raise typer.BadParameter(
            f"{exc} Choose a stronger hidden passphrase or pass --allow-weak-passphrase."
        ) from exc
    except HiddenVolumeError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except ContainerFormatError as exc:
        raise typer.BadParameter(str(exc)) from exc
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
    outer_passphrase: str | None = typer.Option(
        None,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    outer_passphrase_env: str | None = typer.Option(
        None,
        "--outer-passphrase-env",
        help="Environment variable containing the outer-volume passphrase.",
    ),
    outer_passphrase_file: Path | None = typer.Option(
        None,
        "--outer-passphrase-file",
        help="Path to a UTF-8 text file containing the outer-volume passphrase.",
    ),
    inner_passphrase: str | None = typer.Option(
        None,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    inner_passphrase_env: str | None = typer.Option(
        None,
        "--inner-passphrase-env",
        help="Environment variable containing the hidden-volume passphrase.",
    ),
    inner_passphrase_file: Path | None = typer.Option(
        None,
        "--inner-passphrase-file",
        help="Path to a UTF-8 text file containing the hidden-volume passphrase.",
    ),
) -> None:
    """List authenticated contents of the hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_outer_passphrase = require_named_passphrase(
        option_name="outer-passphrase",
        direct=outer_passphrase,
        env_name=outer_passphrase_env,
        file_path=outer_passphrase_file,
        prompt_text="Outer vault passphrase",
    )
    resolved_inner_passphrase = require_named_passphrase(
        option_name="inner-passphrase",
        direct=inner_passphrase,
        env_name=inner_passphrase_env,
        file_path=inner_passphrase_file,
        prompt_text="Hidden volume passphrase",
    )
    try:
        files = VaultService.list_hidden_files(
            vault_path,
            outer_passphrase=resolved_outer_passphrase,
            inner_passphrase=resolved_inner_passphrase,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create the outer vault first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the outer and inner passphrases and try again."
        ) from exc
    except HiddenVolumeError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except ContainerFormatError as exc:
        raise typer.BadParameter(str(exc)) from exc
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


@app.command("info")
def hidden_info_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    outer_passphrase: str | None = typer.Option(
        None,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    outer_passphrase_env: str | None = typer.Option(
        None,
        "--outer-passphrase-env",
        help="Environment variable containing the outer-volume passphrase.",
    ),
    outer_passphrase_file: Path | None = typer.Option(
        None,
        "--outer-passphrase-file",
        help="Path to a UTF-8 text file containing the outer-volume passphrase.",
    ),
    inner_passphrase: str | None = typer.Option(
        None,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    inner_passphrase_env: str | None = typer.Option(
        None,
        "--inner-passphrase-env",
        help="Environment variable containing the hidden-volume passphrase.",
    ),
    inner_passphrase_file: Path | None = typer.Option(
        None,
        "--inner-passphrase-file",
        help="Path to a UTF-8 text file containing the hidden-volume passphrase.",
    ),
) -> None:
    """Show authenticated hidden-volume metadata."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_outer_passphrase = require_named_passphrase(
        option_name="outer-passphrase",
        direct=outer_passphrase,
        env_name=outer_passphrase_env,
        file_path=outer_passphrase_file,
        prompt_text="Outer vault passphrase",
    )
    resolved_inner_passphrase = require_named_passphrase(
        option_name="inner-passphrase",
        direct=inner_passphrase,
        env_name=inner_passphrase_env,
        file_path=inner_passphrase_file,
        prompt_text="Hidden volume passphrase",
    )
    try:
        info = VaultService.read_hidden_info(
            vault_path,
            outer_passphrase=resolved_outer_passphrase,
            inner_passphrase=resolved_inner_passphrase,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create the outer vault first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the outer and inner passphrases and try again."
        ) from exc
    except HiddenVolumeError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except ContainerFormatError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "vault": str(info.path),
            "mode": "unlocked",
            "active_volume": info.active_volume,
            "format": f"v{info.format_version}",
            "kdf_profile": info.kdf_profile.value,
            "created_at": info.created_at,
            "files": info.file_count,
            "encrypted_size": info.encrypted_size,
        },
        json_mode=state.json,
    )


@app.command("verify")
def hidden_verify_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    outer_passphrase: str | None = typer.Option(
        None,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    outer_passphrase_env: str | None = typer.Option(
        None,
        "--outer-passphrase-env",
        help="Environment variable containing the outer-volume passphrase.",
    ),
    outer_passphrase_file: Path | None = typer.Option(
        None,
        "--outer-passphrase-file",
        help="Path to a UTF-8 text file containing the outer-volume passphrase.",
    ),
    inner_passphrase: str | None = typer.Option(
        None,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    inner_passphrase_env: str | None = typer.Option(
        None,
        "--inner-passphrase-env",
        help="Environment variable containing the hidden-volume passphrase.",
    ),
    inner_passphrase_file: Path | None = typer.Option(
        None,
        "--inner-passphrase-file",
        help="Path to a UTF-8 text file containing the hidden-volume passphrase.",
    ),
) -> None:
    """Verify authenticated hidden-volume contents."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_outer_passphrase = require_named_passphrase(
        option_name="outer-passphrase",
        direct=outer_passphrase,
        env_name=outer_passphrase_env,
        file_path=outer_passphrase_file,
        prompt_text="Outer vault passphrase",
    )
    resolved_inner_passphrase = require_named_passphrase(
        option_name="inner-passphrase",
        direct=inner_passphrase,
        env_name=inner_passphrase_env,
        file_path=inner_passphrase_file,
        prompt_text="Hidden volume passphrase",
    )
    try:
        result = VaultService.verify_hidden(
            vault_path,
            outer_passphrase=resolved_outer_passphrase,
            inner_passphrase=resolved_inner_passphrase,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create the outer vault first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the outer and inner passphrases and try again."
        ) from exc
    except HiddenVolumeError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except ContainerFormatError as exc:
        raise typer.BadParameter(str(exc)) from exc
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


@app.command("add")
def hidden_add_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    sources: list[Path] = typer.Argument(..., help="Source files or directories to add."),
    outer_passphrase: str | None = typer.Option(
        None,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    outer_passphrase_env: str | None = typer.Option(
        None,
        "--outer-passphrase-env",
        help="Environment variable containing the outer-volume passphrase.",
    ),
    outer_passphrase_file: Path | None = typer.Option(
        None,
        "--outer-passphrase-file",
        help="Path to a UTF-8 text file containing the outer-volume passphrase.",
    ),
    inner_passphrase: str | None = typer.Option(
        None,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    inner_passphrase_env: str | None = typer.Option(
        None,
        "--inner-passphrase-env",
        help="Environment variable containing the hidden-volume passphrase.",
    ),
    inner_passphrase_file: Path | None = typer.Option(
        None,
        "--inner-passphrase-file",
        help="Path to a UTF-8 text file containing the hidden-volume passphrase.",
    ),
) -> None:
    """Add files or directories to the hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_outer_passphrase = require_named_passphrase(
        option_name="outer-passphrase",
        direct=outer_passphrase,
        env_name=outer_passphrase_env,
        file_path=outer_passphrase_file,
        prompt_text="Outer vault passphrase",
    )
    resolved_inner_passphrase = require_named_passphrase(
        option_name="inner-passphrase",
        direct=inner_passphrase,
        env_name=inner_passphrase_env,
        file_path=inner_passphrase_file,
        prompt_text="Hidden volume passphrase",
    )
    try:
        added_files = VaultService.add_hidden_paths(
            vault_path,
            outer_passphrase=resolved_outer_passphrase,
            inner_passphrase=resolved_inner_passphrase,
            sources=sources,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create the outer vault first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the outer and inner passphrases and try again."
        ) from exc
    except HiddenVolumeError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except ContainerFormatError as exc:
        raise typer.BadParameter(str(exc)) from exc
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
        help="Internal hidden-volume path to extract. Omit it when using --all.",
    ),
    outer_passphrase: str | None = typer.Option(
        None,
        "--outer-passphrase",
        help="Current outer-volume passphrase.",
        hide_input=True,
    ),
    outer_passphrase_env: str | None = typer.Option(
        None,
        "--outer-passphrase-env",
        help="Environment variable containing the outer-volume passphrase.",
    ),
    outer_passphrase_file: Path | None = typer.Option(
        None,
        "--outer-passphrase-file",
        help="Path to a UTF-8 text file containing the outer-volume passphrase.",
    ),
    inner_passphrase: str | None = typer.Option(
        None,
        "--inner-passphrase",
        help="Passphrase for the hidden volume.",
        hide_input=True,
    ),
    inner_passphrase_env: str | None = typer.Option(
        None,
        "--inner-passphrase-env",
        help="Environment variable containing the hidden-volume passphrase.",
    ),
    inner_passphrase_file: Path | None = typer.Option(
        None,
        "--inner-passphrase-file",
        help="Path to a UTF-8 text file containing the hidden-volume passphrase.",
    ),
    output_dir: Path = typer.Option(
        Path("."),
        "--output",
        help="Output directory for extracted files.",
    ),
    extract_all: bool = typer.Option(
        False,
        "--all",
        help="Extract every stored file from the hidden volume.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Replace existing output files instead of failing safely.",
    ),
) -> None:
    """Extract files from the hidden volume."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    resolved_outer_passphrase = require_named_passphrase(
        option_name="outer-passphrase",
        direct=outer_passphrase,
        env_name=outer_passphrase_env,
        file_path=outer_passphrase_file,
        prompt_text="Outer vault passphrase",
    )
    resolved_inner_passphrase = require_named_passphrase(
        option_name="inner-passphrase",
        direct=inner_passphrase,
        env_name=inner_passphrase_env,
        file_path=inner_passphrase_file,
        prompt_text="Hidden volume passphrase",
    )
    try:
        extracted_files = VaultService.extract_hidden_files(
            vault_path,
            outer_passphrase=resolved_outer_passphrase,
            inner_passphrase=resolved_inner_passphrase,
            output_dir=output_dir,
            internal_path=internal_path,
            extract_all=extract_all,
            overwrite=overwrite,
        )
    except (ContainerFormatError, VaultFileNotFoundError, HiddenVolumeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Vault file not found: {vault_path}. Create the outer vault first or check the path."
        ) from exc
    except CryptoAuthenticationError as exc:
        raise typer.BadParameter(
            f"{exc} Re-enter the outer and inner passphrases and try again."
        ) from exc
    except WeakPassphraseError as exc:
        raise typer.BadParameter(str(exc)) from exc
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
