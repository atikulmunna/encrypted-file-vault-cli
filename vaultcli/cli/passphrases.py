"""Shared passphrase input helpers for CLI commands."""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import typer


def _passphrase_source_labels(*, option_name: str) -> tuple[str, str, str]:
    return (
        f"--{option_name}",
        f"--{option_name}-env",
        f"--{option_name}-file",
    )


def _format_passphrase_source_hint(
    *,
    option_name: str,
    prompt_flag: str | None,
    include_locked_hint: bool = False,
) -> str:
    direct_flag, env_flag, file_flag = _passphrase_source_labels(option_name=option_name)
    hints = [direct_flag, env_flag, file_flag]
    if prompt_flag is not None:
        hints.append(prompt_flag)
    if include_locked_hint:
        hints.append("--locked")
    return ", ".join(hints)


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
        accepted = _format_passphrase_source_hint(
            option_name="passphrase",
            prompt_flag="interactive prompt",
        )
        raise typer.BadParameter(
            f"A passphrase source is required for this command. Use one of: {accepted}."
        )
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
    direct_flag, env_flag, file_flag = _passphrase_source_labels(option_name="passphrase")
    selected_sources = [
        name
        for name, value in (
            (direct_flag, direct),
            (env_flag, env_name),
            (file_flag, file_path),
        )
        if value is not None
    ]
    if len(selected_sources) > 1:
        raise typer.BadParameter(
            f"Choose only one passphrase source: {direct_flag}, {env_flag}, or {file_flag}."
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
        accepted = _format_passphrase_source_hint(
            option_name=option_name,
            prompt_flag="interactive prompt",
        )
        raise typer.BadParameter(
            f"A source for {option_name.replace('-', ' ')} is required. "
            f"Use one of: {accepted}."
        )
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
    direct_flag, env_flag, file_flag = _passphrase_source_labels(option_name=option_name)
    selected_sources = [
        name
        for name, value in (
            (direct_flag, direct),
            (env_flag, env_name),
            (file_flag, file_path),
        )
        if value is not None
    ]
    if len(selected_sources) > 1:
        raise typer.BadParameter(
            f"Choose only one source for {option_name.replace('-', ' ')}: "
            f"{direct_flag}, {env_flag}, or {file_flag}."
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
        raise typer.BadParameter(
            f"Environment variable {env_name!r} is not set. "
            f"Set it first or choose --passphrase / --passphrase-file instead."
        ) from exc


def _read_passphrase_file(file_path: Path) -> str:
    try:
        value = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(
            f"Could not read passphrase file: {file_path}. "
            f"Check the path and file permissions, or choose another passphrase source."
        ) from exc

    return value.rstrip("\r\n")
