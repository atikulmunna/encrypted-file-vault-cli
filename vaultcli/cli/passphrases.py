"""Shared passphrase input helpers for CLI commands."""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import typer


def require_passphrase(
    *,
    direct: str | None,
    env_name: str | None,
    file_path: Path | None,
    prompt_text: str,
    confirm: bool = False,
    allow_prompt: bool = True,
) -> str:
    """Resolve a required passphrase from direct input, env, file, or an interactive prompt."""
    value = resolve_passphrase(
        direct=direct,
        env_name=env_name,
        file_path=file_path,
        prompt_text=prompt_text,
        confirm=confirm,
        allow_prompt=allow_prompt,
    )
    if value is None:
        raise typer.BadParameter("A passphrase source is required for this command.")
    return value


def resolve_passphrase(
    *,
    direct: str | None,
    env_name: str | None,
    file_path: Path | None,
    prompt_text: str,
    confirm: bool = False,
    allow_prompt: bool = True,
) -> str | None:
    """Resolve a passphrase from direct input, env, file, or an interactive prompt."""
    selected_sources = [
        name
        for name, value in (
            ("--passphrase", direct),
            ("--passphrase-env", env_name),
            ("--passphrase-file", file_path),
        )
        if value is not None
    ]
    if len(selected_sources) > 1:
        raise typer.BadParameter(
            "Choose only one passphrase source: direct value, env var, or file."
        )

    if direct is not None:
        return direct
    if env_name is not None:
        return _read_passphrase_env(env_name)
    if file_path is not None:
        return _read_passphrase_file(file_path)
    if allow_prompt:
        return cast(
            str,
            typer.prompt(
            prompt_text,
            hide_input=True,
            confirmation_prompt=confirm,
            ),
        )
    return None


def require_named_passphrase(
    *,
    option_name: str,
    direct: str | None,
    env_name: str | None,
    file_path: Path | None,
    prompt_text: str,
    confirm: bool = False,
    allow_prompt: bool = True,
) -> str:
    """Resolve a required specifically named passphrase input."""
    value = resolve_named_passphrase(
        option_name=option_name,
        direct=direct,
        env_name=env_name,
        file_path=file_path,
        prompt_text=prompt_text,
        confirm=confirm,
        allow_prompt=allow_prompt,
    )
    if value is None:
        raise typer.BadParameter(f"A source for {option_name.replace('-', ' ')} is required.")
    return value


def resolve_named_passphrase(
    *,
    option_name: str,
    direct: str | None,
    env_name: str | None,
    file_path: Path | None,
    prompt_text: str,
    confirm: bool = False,
    allow_prompt: bool = True,
) -> str | None:
    """Resolve a specifically named passphrase input with matching option labels."""
    selected_sources = [
        name
        for name, value in (
            (f"--{option_name}", direct),
            (f"--{option_name}-env", env_name),
            (f"--{option_name}-file", file_path),
        )
        if value is not None
    ]
    if len(selected_sources) > 1:
        raise typer.BadParameter(
            f"Choose only one source for {option_name.replace('-', ' ')}."
        )

    if direct is not None:
        return direct
    if env_name is not None:
        return _read_passphrase_env(env_name)
    if file_path is not None:
        return _read_passphrase_file(file_path)
    if allow_prompt:
        return cast(
            str,
            typer.prompt(
            prompt_text,
            hide_input=True,
            confirmation_prompt=confirm,
            ),
        )
    return None


def _read_passphrase_env(env_name: str) -> str:
    try:
        return os.environ[env_name]
    except KeyError as exc:
        raise typer.BadParameter(f"Environment variable {env_name!r} is not set.") from exc


def _read_passphrase_file(file_path: Path) -> str:
    try:
        value = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(f"Could not read passphrase file: {file_path}") from exc

    return value.rstrip("\r\n")
