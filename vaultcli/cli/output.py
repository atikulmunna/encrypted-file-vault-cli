"""Shared CLI output helpers."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console

console = Console()


def emit(data: dict[str, Any], *, json_mode: bool) -> None:
    """Emit structured command output in text or JSON form."""
    if json_mode:
        console.print_json(json.dumps(data))
        return

    for key, value in data.items():
        label = key.replace("_", " ").title()
        console.print(f"{label}: {value}")
