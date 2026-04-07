"""Best-effort plaintext file wiping helpers."""

from __future__ import annotations

import os
from pathlib import Path
import secrets

from vaultcli.errors import WipeError


def wipe_file(path: str | Path, *, passes: int = 3) -> Path:
    """Overwrite a regular file for a number of passes, then delete it."""
    target = Path(path)
    if passes <= 0:
        raise WipeError("Wipe passes must be a positive integer.")
    if not target.exists():
        raise WipeError(f"Path does not exist: {target}")
    if not target.is_file():
        raise WipeError(f"Wipe currently supports regular files only: {target}")

    file_size = target.stat().st_size
    with target.open("r+b", buffering=0) as handle:
        for _ in range(passes):
            handle.seek(0)
            if file_size > 0:
                handle.write(secrets.token_bytes(file_size))
            handle.flush()
            os.fsync(handle.fileno())

    target.unlink()
    return target
