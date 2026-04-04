"""AES-256-GCM helpers for DEK wrapping and chunk encryption."""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultcli.errors import CryptoAuthenticationError, CryptoInputError


AES256_KEY_BYTES = 32
GCM_NONCE_BYTES = 12


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """Encrypted bytes paired with the nonce used to produce them."""

    nonce: bytes
    ciphertext: bytes


class EncryptionService:
    """Perform AES-256-GCM encryption and decryption operations."""

    @staticmethod
    def generate_dek() -> bytes:
        """Generate a random 256-bit data-encryption key."""
        return secrets.token_bytes(AES256_KEY_BYTES)

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a random 96-bit GCM nonce."""
        return secrets.token_bytes(GCM_NONCE_BYTES)

    @classmethod
    def wrap_dek(
        cls,
        kek: bytes,
        dek: bytes,
        aad: bytes,
        nonce: bytes | None = None,
    ) -> EncryptedPayload:
        """Encrypt a DEK using a KEK and authenticated metadata."""
        cls._validate_key(kek, label="KEK")
        cls._validate_key(dek, label="DEK")

        resolved_nonce = nonce or cls.generate_nonce()
        cls._validate_nonce(resolved_nonce)

        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(resolved_nonce, dek, aad)

        return EncryptedPayload(nonce=resolved_nonce, ciphertext=ciphertext)

    @classmethod
    def unwrap_dek(
        cls,
        kek: bytes,
        wrapped_dek: EncryptedPayload,
        aad: bytes,
    ) -> bytes:
        """Decrypt a wrapped DEK using its KEK and authenticated metadata."""
        cls._validate_key(kek, label="KEK")
        cls._validate_nonce(wrapped_dek.nonce)

        aesgcm = AESGCM(kek)

        try:
            plaintext = aesgcm.decrypt(wrapped_dek.nonce, wrapped_dek.ciphertext, aad)
        except InvalidTag as exc:
            raise CryptoAuthenticationError("DEK unwrap failed authentication.") from exc

        cls._validate_key(plaintext, label="DEK")
        return plaintext

    @classmethod
    def encrypt_chunk(
        cls,
        key: bytes,
        plaintext: bytes,
        aad: bytes,
        nonce: bytes | None = None,
    ) -> EncryptedPayload:
        """Encrypt a chunk of file data with AES-256-GCM."""
        cls._validate_key(key, label="AES-256 key")

        resolved_nonce = nonce or cls.generate_nonce()
        cls._validate_nonce(resolved_nonce)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(resolved_nonce, plaintext, aad)

        return EncryptedPayload(nonce=resolved_nonce, ciphertext=ciphertext)

    @classmethod
    def decrypt_chunk(cls, key: bytes, payload: EncryptedPayload, aad: bytes) -> bytes:
        """Decrypt a chunk of file data and verify its authentication tag."""
        cls._validate_key(key, label="AES-256 key")
        cls._validate_nonce(payload.nonce)

        aesgcm = AESGCM(key)

        try:
            return aesgcm.decrypt(payload.nonce, payload.ciphertext, aad)
        except InvalidTag as exc:
            raise CryptoAuthenticationError("Chunk decryption failed authentication.") from exc

    @staticmethod
    def _validate_key(key: bytes, *, label: str) -> None:
        if len(key) != AES256_KEY_BYTES:
            raise CryptoInputError(f"{label} must be exactly {AES256_KEY_BYTES} bytes.")

    @staticmethod
    def _validate_nonce(nonce: bytes) -> None:
        if len(nonce) != GCM_NONCE_BYTES:
            raise CryptoInputError(f"Nonce must be exactly {GCM_NONCE_BYTES} bytes.")
