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
        _print_value(label, value)


def _print_value(label: str, value: Any) -> None:
    if isinstance(value, list):
        console.print(f"{label}:")
        if not value:
            console.print("  - none")
            return
        for item in value:
            if isinstance(item, dict):
                summary = ", ".join(
                    f"{item_key.replace('_', ' ')}={item_value}"
                    for item_key, item_value in item.items()
                )
                console.print(f"  - {summary}")
            else:
                console.print(f"  - {item}")
        return

    if isinstance(value, dict):
        console.print(f"{label}:")
        for item_key, item_value in value.items():
            console.print(f"  {item_key.replace('_', ' ').title()}: {item_value}")
        return

    console.print(f"{label}: {value}")
