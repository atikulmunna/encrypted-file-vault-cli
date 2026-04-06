"""Tests for passphrase policy helpers."""

import pytest

from vaultcli.errors import WeakPassphraseError
from vaultcli.passphrases import (
    MINIMUM_PASSPHRASE_BITS,
    enforce_passphrase_policy,
    estimate_passphrase_entropy_bits,
)


def test_estimate_entropy_increases_with_stronger_passphrase() -> None:
    weak_bits = estimate_passphrase_entropy_bits("password123")
    strong_bits = estimate_passphrase_entropy_bits("Xk9#mP2$vQr7!nL")

    assert weak_bits < strong_bits


def test_enforce_passphrase_policy_rejects_weak_passphrase_by_default() -> None:
    with pytest.raises(WeakPassphraseError):
        enforce_passphrase_policy("password123")


def test_enforce_passphrase_policy_allows_override_for_weak_passphrase() -> None:
    bits = enforce_passphrase_policy("password123", allow_weak=True)

    assert bits < MINIMUM_PASSPHRASE_BITS
