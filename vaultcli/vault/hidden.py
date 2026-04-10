"""Helpers for hidden-volume region construction and parsing."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final

from vaultcli.container.index import VolumeIndex, deserialize_index, serialize_index
from vaultcli.crypto.aes_gcm import EncryptedPayload, EncryptionService
from vaultcli.crypto.kdf import KdfProfileName, KdfService
from vaultcli.errors import ContainerFormatError, CryptoAuthenticationError, HiddenVolumeError

HIDDEN_INDEX_AAD: Final[bytes] = b"vaultcli:hidden-index"
HIDDEN_HEADER_AAD: Final[bytes] = b"vaultcli:hidden-header"
HIDDEN_SALT_BYTES: Final[int] = 32
HIDDEN_WRAPPED_DEK_BYTES: Final[int] = 48
HIDDEN_NONCE_BYTES: Final[int] = 12
HIDDEN_INDEX_SIZE_BYTES: Final[int] = 4
HIDDEN_REGION_FIXED_BYTES: Final[int] = (
    HIDDEN_SALT_BYTES + HIDDEN_NONCE_BYTES + HIDDEN_WRAPPED_DEK_BYTES + HIDDEN_INDEX_SIZE_BYTES
)


@dataclass(frozen=True, slots=True)
class HiddenRegionRecord:
    """Parsed hidden-region fields from the reserved tail."""

    salt: bytes
    wrapped_dek: EncryptedPayload
    encrypted_index: bytes
    encrypted_data_and_padding: bytes
    total_size: int


@dataclass(frozen=True, slots=True)
class UnlockedHiddenRegion:
    """Authenticated hidden-volume material for subsequent operations."""

    record: HiddenRegionRecord
    dek: bytes
    index: VolumeIndex
    encrypted_data: bytes


def build_hidden_region(
    *,
    passphrase: str,
    kdf_profile: KdfProfileName,
    hidden_size: int,
) -> bytes:
    """Create an empty hidden-volume region padded to the requested size."""
    if hidden_size <= HIDDEN_REGION_FIXED_BYTES:
        raise HiddenVolumeError(
            f"Hidden volume size must be larger than {HIDDEN_REGION_FIXED_BYTES} bytes."
        )

    salt = secrets.token_bytes(HIDDEN_SALT_BYTES)
    kek = KdfService.derive_key(passphrase, salt, kdf_profile)
    dek = EncryptionService.generate_dek()
    wrapped_dek = EncryptionService.wrap_dek(kek, dek, HIDDEN_HEADER_AAD)
    empty_index = VolumeIndex(
        version=1,
        created_at=0,
        reserved_tail_start=None,
        files=(),
    )
    encrypted_index = _encrypt_hidden_index(empty_index, dek)

    required_bytes = HIDDEN_REGION_FIXED_BYTES + len(encrypted_index)
    if hidden_size < required_bytes:
        raise HiddenVolumeError(
            f"Hidden volume size {hidden_size} is too small; need at least {required_bytes} bytes."
        )

    padding = secrets.token_bytes(hidden_size - required_bytes)
    return b"".join(
        [
            salt,
            wrapped_dek.nonce,
            wrapped_dek.ciphertext,
            len(encrypted_index).to_bytes(4, "big"),
            encrypted_index,
            padding,
        ]
    )


def _encrypt_hidden_index(index: VolumeIndex, dek: bytes) -> bytes:
    payload = EncryptionService.encrypt_chunk(dek, serialize_index(index), HIDDEN_INDEX_AAD)
    return payload.nonce + payload.ciphertext


def parse_hidden_region(region: bytes) -> HiddenRegionRecord:
    """Parse the opaque hidden tail into its authenticated components."""
    if len(region) <= HIDDEN_REGION_FIXED_BYTES:
        raise HiddenVolumeError("Reserved tail is too small to contain a hidden region.")

    salt_end = HIDDEN_SALT_BYTES
    nonce_end = salt_end + HIDDEN_NONCE_BYTES
    wrapped_end = nonce_end + HIDDEN_WRAPPED_DEK_BYTES
    index_size_end = wrapped_end + HIDDEN_INDEX_SIZE_BYTES

    encrypted_index_size = int.from_bytes(region[wrapped_end:index_size_end], "big")
    if encrypted_index_size <= HIDDEN_NONCE_BYTES:
        raise HiddenVolumeError("Hidden index payload is too small to contain a nonce.")

    index_end = index_size_end + encrypted_index_size
    if index_end > len(region):
        raise HiddenVolumeError("Hidden index extends beyond the reserved tail.")

    return HiddenRegionRecord(
        salt=region[:salt_end],
        wrapped_dek=EncryptedPayload(
            nonce=region[salt_end:nonce_end],
            ciphertext=region[nonce_end:wrapped_end],
        ),
        encrypted_index=region[index_size_end:index_end],
        encrypted_data_and_padding=region[index_end:],
        total_size=len(region),
    )


def unlock_hidden_region(
    region: bytes,
    *,
    passphrase: str,
    kdf_profile: KdfProfileName,
) -> UnlockedHiddenRegion:
    """Authenticate and unlock a parsed hidden region."""
    record = parse_hidden_region(region)
    kek = KdfService.derive_key(passphrase, record.salt, kdf_profile)

    try:
        dek = EncryptionService.unwrap_dek(kek, record.wrapped_dek, HIDDEN_HEADER_AAD)
    except CryptoAuthenticationError as exc:
        raise CryptoAuthenticationError(
            "Hidden volume unlock failed: wrong passphrase or corrupted hidden header."
        ) from exc

    index = _decrypt_hidden_index(record.encrypted_index, dek)
    used_bytes = _used_hidden_data_bytes(index)
    if used_bytes > len(record.encrypted_data_and_padding):
        raise HiddenVolumeError("Hidden file data extends beyond the reserved tail size.")

    return UnlockedHiddenRegion(
        record=record,
        dek=dek,
        index=index,
        encrypted_data=record.encrypted_data_and_padding[:used_bytes],
    )


def serialize_hidden_region(
    *,
    passphrase: str,
    kdf_profile: KdfProfileName,
    dek: bytes,
    index: VolumeIndex,
    encrypted_data: bytes,
    total_size: int,
    salt: bytes | None = None,
) -> bytes:
    """Serialize a hidden region while preserving its reserved total size."""
    if total_size <= HIDDEN_REGION_FIXED_BYTES:
        raise HiddenVolumeError("Reserved tail is too small to store a hidden region.")

    region_salt = salt or secrets.token_bytes(HIDDEN_SALT_BYTES)
    kek = KdfService.derive_key(passphrase, region_salt, kdf_profile)
    wrapped_dek = EncryptionService.wrap_dek(kek, dek, HIDDEN_HEADER_AAD)
    encrypted_index = _encrypt_hidden_index(index, dek)

    required_bytes = HIDDEN_REGION_FIXED_BYTES + len(encrypted_index) + len(encrypted_data)
    if required_bytes > total_size:
        raise HiddenVolumeError("Hidden volume is full; not enough reserved space remains.")

    padding = secrets.token_bytes(total_size - required_bytes)
    return b"".join(
        [
            region_salt,
            wrapped_dek.nonce,
            wrapped_dek.ciphertext,
            len(encrypted_index).to_bytes(4, "big"),
            encrypted_index,
            encrypted_data,
            padding,
        ]
    )


def _decrypt_hidden_index(encrypted_index: bytes, dek: bytes) -> VolumeIndex:
    if len(encrypted_index) <= HIDDEN_NONCE_BYTES:
        raise HiddenVolumeError("Hidden index payload is too small to contain a nonce.")

    nonce = encrypted_index[:HIDDEN_NONCE_BYTES]
    ciphertext = encrypted_index[HIDDEN_NONCE_BYTES:]
    try:
        plaintext = EncryptionService.decrypt_chunk(
            dek,
            EncryptedPayload(nonce=nonce, ciphertext=ciphertext),
            HIDDEN_INDEX_AAD,
        )
    except CryptoAuthenticationError as exc:
        raise CryptoAuthenticationError(
            "Hidden volume unlock failed: wrong passphrase or corrupted hidden index."
        ) from exc

    try:
        return deserialize_index(plaintext)
    except ContainerFormatError as exc:
        raise HiddenVolumeError("Hidden index could not be decoded.") from exc


def _used_hidden_data_bytes(index: VolumeIndex) -> int:
    used = 0
    for file_record in index.files:
        for chunk in file_record.chunks:
            used = max(used, chunk.offset + chunk.ciphertext_size)
    return used
