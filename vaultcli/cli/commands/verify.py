"""Placeholder implementation for `vault verify`."""

from __future__ import annotations

from pathlib import Path

import typer

from vaultcli.cli.output import emit
from vaultcli.cli.passphrases import resolve_passphrase
from vaultcli.cli.state import AppState
from vaultcli.vault import VaultService


def verify_command(
    ctx: typer.Context,
    vault_path: Path = typer.Argument(..., help="Path to the target vault container."),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Unlock the vault to verify authenticated contents.",
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
        help="Prompt for the vault passphrase before authenticated verification.",
    ),
    locked: bool = typer.Option(
        False,
        "--locked",
        help="Run structural-only verification without authenticating ciphertext.",
    ),
) -> None:
    """Verify a vault container."""
    state = ctx.obj if isinstance(ctx.obj, AppState) else AppState()
    if locked:
        result = VaultService.verify_locked(vault_path)
    else:
        resolved_passphrase = resolve_passphrase(
            direct=passphrase,
            env_name=passphrase_env,
            file_path=passphrase_file,
            prompt_text="Vault passphrase",
            allow_prompt=prompt_passphrase,
        )
        if resolved_passphrase is None:
            typer.echo(
                "Pass --passphrase, --passphrase-env, --passphrase-file, "
                "--prompt-passphrase, or use --locked.",
                err=True,
            )
            raise typer.Exit(code=2)
        result = VaultService.verify_unlocked(vault_path, passphrase=resolved_passphrase)

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
