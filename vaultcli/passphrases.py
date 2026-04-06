"""Passphrase policy helpers for VaultCLI."""

from __future__ import annotations

import math
import string

from vaultcli.errors import WeakPassphraseError


MINIMUM_PASSPHRASE_BITS = 60.0


def estimate_passphrase_entropy_bits(passphrase: str) -> float:
    """Estimate passphrase entropy with a conservative character-set heuristic."""
    if not passphrase:
        return 0.0

    charset = 0
    if any(character.islower() for character in passphrase):
        charset += 26
    if any(character.isupper() for character in passphrase):
        charset += 26
    if any(character.isdigit() for character in passphrase):
        charset += 10
    if any(character in string.punctuation for character in passphrase):
        charset += len(string.punctuation)
    if any(character.isspace() for character in passphrase):
        charset += 1

    if charset == 0:
        charset = len(set(passphrase))

    return len(passphrase) * math.log2(charset)


def enforce_passphrase_policy(passphrase: str, *, allow_weak: bool = False) -> float:
    """Validate a passphrase against the current default policy and return its estimate."""
    entropy_bits = estimate_passphrase_entropy_bits(passphrase)
    if entropy_bits < MINIMUM_PASSPHRASE_BITS and not allow_weak:
        raise WeakPassphraseError(
            f"Passphrase estimated at {entropy_bits:.1f} bits; minimum is {MINIMUM_PASSPHRASE_BITS:.0f} bits."
        )
    return entropy_bits
