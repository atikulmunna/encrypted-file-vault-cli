"""Tests for AES-256-GCM encryption helpers."""

import pytest

from vaultcli.crypto.aes_gcm import AES256_KEY_BYTES, EncryptionService, EncryptedPayload
from vaultcli.errors import CryptoAuthenticationError, CryptoInputError


def test_generate_dek_returns_random_32_byte_key() -> None:
    dek_a = EncryptionService.generate_dek()
    dek_b = EncryptionService.generate_dek()

    assert len(dek_a) == AES256_KEY_BYTES
    assert len(dek_b) == AES256_KEY_BYTES
    assert dek_a != dek_b


def test_wrap_and_unwrap_dek_round_trip() -> None:
    kek = bytes(range(AES256_KEY_BYTES))
    dek = EncryptionService.generate_dek()
    aad = b"vault-header-bytes"

    wrapped = EncryptionService.wrap_dek(kek, dek, aad)
    unwrapped = EncryptionService.unwrap_dek(kek, wrapped, aad)

    assert unwrapped == dek


def test_unwrap_dek_fails_when_ciphertext_is_tampered() -> None:
    kek = bytes(range(AES256_KEY_BYTES))
    dek = EncryptionService.generate_dek()
    aad = b"vault-header-bytes"
    wrapped = EncryptionService.wrap_dek(kek, dek, aad)
    tampered = EncryptedPayload(
        nonce=wrapped.nonce,
        ciphertext=wrapped.ciphertext[:-1] + bytes([wrapped.ciphertext[-1] ^ 0x01]),
    )

    with pytest.raises(CryptoAuthenticationError):
        EncryptionService.unwrap_dek(kek, tampered, aad)


def test_encrypt_and_decrypt_chunk_round_trip() -> None:
    key = EncryptionService.generate_dek()
    aad = b"documents/secret.txt|chunk=0|final=1"
    plaintext = b"super secret bytes"

    payload = EncryptionService.encrypt_chunk(key, plaintext, aad)

    assert EncryptionService.decrypt_chunk(key, payload, aad) == plaintext


def test_decrypt_chunk_fails_with_wrong_aad() -> None:
    key = EncryptionService.generate_dek()
    payload = EncryptionService.encrypt_chunk(key, b"payload", b"path=a")

    with pytest.raises(CryptoAuthenticationError):
        EncryptionService.decrypt_chunk(key, payload, b"path=b")


def test_encrypt_chunk_rejects_wrong_key_size() -> None:
    with pytest.raises(CryptoInputError):
        EncryptionService.encrypt_chunk(b"short-key", b"payload", b"aad")
