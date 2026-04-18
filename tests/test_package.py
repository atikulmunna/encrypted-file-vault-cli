"""Bootstrap tests for the initial project scaffold."""

from vaultcli import __version__
from vaultcli.errors import VaultCliError


def test_package_exposes_version() -> None:
    assert __version__ == "0.1.0rc1"


def test_base_error_is_exception() -> None:
    assert issubclass(VaultCliError, Exception)
