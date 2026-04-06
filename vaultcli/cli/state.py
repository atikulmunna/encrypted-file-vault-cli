"""Shared CLI state objects."""


class AppState:
    """Per-invocation CLI state."""

    def __init__(self) -> None:
        self.verbose = False
        self.json = False
