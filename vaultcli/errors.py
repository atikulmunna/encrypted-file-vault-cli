"""Shared exception types for VaultCLI."""


class VaultCliError(Exception):
    """Base exception for VaultCLI."""


class KdfProfileError(VaultCliError):
    """Raised when KDF profile resolution fails."""


class KdfInputError(VaultCliError):
    """Raised when KDF inputs are invalid."""
