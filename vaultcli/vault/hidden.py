"""Helpers for hidden-volume region construction."""

from __future__ import annotations

import secrets
from typing import Final

from vaultcli.container.index import VolumeIndex, serialize_index
from vaultcli.crypto.aes_gcm import EncryptionService
from vaultcli.crypto.kdf import KdfProfileName, KdfService
from vaultcli.errors import HiddenVolumeError


HIDDEN_INDEX_AAD: Final[bytes] = b"vaultcli:hidden-index"
HIDDEN_HEADER_AAD: Final[bytes] = b"vaultcli:hidden-header"
HIDDEN_SALT_BYTES: Final[int] = 32
HIDDEN_WRAPPED_DEK_BYTES: Final[int] = 48
HIDDEN_NONCE_BYTES: Final[int] = 12
HIDDEN_INDEX_SIZE_BYTES: Final[int] = 4
HIDDEN_REGION_FIXED_BYTES: Final[int] = (
    HIDDEN_SALT_BYTES + HIDDEN_NONCE_BYTES + HIDDEN_WRAPPED_DEK_BYTES + HIDDEN_INDEX_SIZE_BYTES
)


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
