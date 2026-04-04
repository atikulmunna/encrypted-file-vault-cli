"""Tests for the Argon2id KDF service."""

import secrets

import pytest

from vaultcli.crypto.kdf import KDF_PROFILES, KDF_KEY_BYTES, KDF_SALT_BYTES, KdfProfileName, KdfService
from vaultcli.errors import KdfInputError, KdfProfileError


def test_resolve_profile_accepts_string_name() -> None:
    profile = KdfService.resolve_profile("interactive")

    assert profile == KDF_PROFILES[KdfProfileName.INTERACTIVE]


def test_resolve_profile_rejects_unknown_name() -> None:
    with pytest.raises(KdfProfileError):
        KdfService.resolve_profile("unknown")


def test_derive_key_is_deterministic_for_same_inputs() -> None:
    salt = bytes(range(KDF_SALT_BYTES))

    key_a = KdfService.derive_key("hunter2-but-better", salt, "bulk")
    key_b = KdfService.derive_key("hunter2-but-better", salt, KdfProfileName.BULK)

    assert key_a == key_b
    assert len(key_a) == KDF_KEY_BYTES


def test_derive_key_changes_when_salt_changes() -> None:
    passphrase = "diceware-passphrase-example"
    salt_a = bytes(range(KDF_SALT_BYTES))
    salt_b = secrets.token_bytes(KDF_SALT_BYTES)

    key_a = KdfService.derive_key(passphrase, salt_a, "bulk")
    key_b = KdfService.derive_key(passphrase, salt_b, "bulk")

    assert key_a != key_b


def test_derive_key_rejects_empty_passphrase() -> None:
    with pytest.raises(KdfInputError):
        KdfService.derive_key("", bytes(range(KDF_SALT_BYTES)))


def test_derive_key_rejects_wrong_salt_length() -> None:
    with pytest.raises(KdfInputError):
        KdfService.derive_key("valid-passphrase", b"short-salt", "interactive")
