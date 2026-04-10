"""Argon2id key-derivation service and named profiles."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from argon2.low_level import Type, hash_secret_raw

from vaultcli.errors import KdfInputError, KdfProfileError

KDF_SALT_BYTES = 32
KDF_KEY_BYTES = 32


class KdfProfileName(StrEnum):
    """Supported named KDF profiles."""

    INTERACTIVE = "interactive"
    SENSITIVE = "sensitive"
    BULK = "bulk"


@dataclass(frozen=True, slots=True)
class KdfProfile:
    """A validated Argon2id profile."""

    name: KdfProfileName
    memory_cost_kib: int
    time_cost: int
    parallelism: int
    hash_len: int = KDF_KEY_BYTES
    salt_len: int = KDF_SALT_BYTES


KDF_PROFILES: dict[KdfProfileName, KdfProfile] = {
    KdfProfileName.INTERACTIVE: KdfProfile(
        name=KdfProfileName.INTERACTIVE,
        memory_cost_kib=65536,
        time_cost=3,
        parallelism=4,
    ),
    KdfProfileName.SENSITIVE: KdfProfile(
        name=KdfProfileName.SENSITIVE,
        memory_cost_kib=262144,
        time_cost=4,
        parallelism=4,
    ),
    KdfProfileName.BULK: KdfProfile(
        name=KdfProfileName.BULK,
        memory_cost_kib=19456,
        time_cost=2,
        parallelism=1,
    ),
}


class KdfService:
    """Derive KEKs from passphrases using Argon2id."""

    @staticmethod
    def resolve_profile(profile: str | KdfProfileName | KdfProfile) -> KdfProfile:
        """Resolve a caller-supplied profile reference to a concrete profile."""
        if isinstance(profile, KdfProfile):
            return profile

        try:
            profile_name = (
                profile if isinstance(profile, KdfProfileName) else KdfProfileName(profile.lower())
            )
        except ValueError as exc:
            raise KdfProfileError(f"Unsupported KDF profile: {profile!r}") from exc

        return KDF_PROFILES[profile_name]

    @classmethod
    def derive_key(
        cls,
        passphrase: str | bytes,
        salt: bytes,
        profile: str | KdfProfileName | KdfProfile = KdfProfileName.INTERACTIVE,
    ) -> bytes:
        """Derive a 32-byte key from a passphrase and salt."""
        resolved_profile = cls.resolve_profile(profile)
        encoded_passphrase = cls._normalize_passphrase(passphrase)
        cls._validate_salt(salt, expected_len=resolved_profile.salt_len)

        return hash_secret_raw(
            secret=encoded_passphrase,
            salt=salt,
            time_cost=resolved_profile.time_cost,
            memory_cost=resolved_profile.memory_cost_kib,
            parallelism=resolved_profile.parallelism,
            hash_len=resolved_profile.hash_len,
            type=Type.ID,
        )

    @staticmethod
    def _normalize_passphrase(passphrase: str | bytes) -> bytes:
        if isinstance(passphrase, str):
            encoded = passphrase.encode("utf-8")
        else:
            encoded = passphrase

        if not encoded:
            raise KdfInputError("Passphrase must not be empty.")

        return encoded

    @staticmethod
    def _validate_salt(salt: bytes, expected_len: int) -> None:
        if len(salt) != expected_len:
            raise KdfInputError(
                f"Salt must be exactly {expected_len} bytes for this profile; got {len(salt)}."
            )
