"""Shared exception types for VaultCLI."""


class VaultCliError(Exception):
    """Base exception for VaultCLI."""


class KdfProfileError(VaultCliError):
    """Raised when KDF profile resolution fails."""


class KdfInputError(VaultCliError):
    """Raised when KDF inputs are invalid."""


class CryptoInputError(VaultCliError):
    """Raised when cryptographic inputs are invalid."""


class CryptoAuthenticationError(VaultCliError):
    """Raised when authenticated decryption fails."""


class ContainerFormatError(VaultCliError):
    """Raised when container headers or index data are malformed."""


class VaultFileNotFoundError(VaultCliError):
    """Raised when a requested internal vault path is missing."""


class WeakPassphraseError(VaultCliError):
    """Raised when a passphrase is rejected by policy."""


class WipeError(VaultCliError):
    """Raised when a wipe operation cannot be completed safely."""
