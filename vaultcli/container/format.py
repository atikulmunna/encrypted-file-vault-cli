"""Binary format helpers for the public vault header."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import cast

from vaultcli.crypto.kdf import KdfProfileName
from vaultcli.errors import ContainerFormatError

MAGIC = b"VAULTCLI"
FORMAT_VERSION = 1
PUBLIC_HEADER_STRUCT = struct.Struct(">8sHBBQ12s")
PUBLIC_HEADER_SIZE = PUBLIC_HEADER_STRUCT.size
RESERVED_BYTES = b"\x00" * 12
OUTER_SALT_BYTES = 32
DEK_NONCE_BYTES = 12
WRAPPED_DEK_BYTES = 48
INDEX_SIZE_BYTES = 4
OUTER_SALT_OFFSET = PUBLIC_HEADER_SIZE
OUTER_DEK_NONCE_OFFSET = OUTER_SALT_OFFSET + OUTER_SALT_BYTES
WRAPPED_DEK_OFFSET = OUTER_DEK_NONCE_OFFSET + DEK_NONCE_BYTES
INDEX_SIZE_OFFSET = WRAPPED_DEK_OFFSET + WRAPPED_DEK_BYTES
INDEX_DATA_OFFSET = INDEX_SIZE_OFFSET + INDEX_SIZE_BYTES

KDF_PROFILE_IDS: dict[KdfProfileName, int] = {
    KdfProfileName.INTERACTIVE: 0x00,
    KdfProfileName.SENSITIVE: 0x01,
    KdfProfileName.BULK: 0x02,
}
KDF_PROFILE_NAMES = {value: key for key, value in KDF_PROFILE_IDS.items()}


@dataclass(frozen=True, slots=True)
class PublicHeader:
    """Public, non-sensitive vault header fields."""

    version: int = FORMAT_VERSION
    flags: int = 0
    kdf_profile: KdfProfileName = KdfProfileName.INTERACTIVE
    container_size: int = 0


def pack_public_header(header: PublicHeader) -> bytes:
    """Pack a validated public header into its 32-byte binary form."""
    if header.version != FORMAT_VERSION:
        raise ContainerFormatError(
            f"Unsupported format version for packing: {header.version}."
        )
    if not 0 <= header.flags <= 0xFF:
        raise ContainerFormatError("Public header flags must fit in one byte.")
    if header.container_size < 0:
        raise ContainerFormatError("Container size must be non-negative.")

    try:
        kdf_profile_id = KDF_PROFILE_IDS[header.kdf_profile]
    except KeyError as exc:
        raise ContainerFormatError(f"Unsupported KDF profile: {header.kdf_profile!r}") from exc

    return PUBLIC_HEADER_STRUCT.pack(
        MAGIC,
        header.version,
        header.flags,
        kdf_profile_id,
        header.container_size,
        RESERVED_BYTES,
    )


def parse_public_header(data: bytes) -> PublicHeader:
    """Parse and validate a packed 32-byte public header."""
    if len(data) != PUBLIC_HEADER_SIZE:
        raise ContainerFormatError(
            f"Public header must be exactly {PUBLIC_HEADER_SIZE} bytes; got {len(data)}."
        )

    magic, version, flags, kdf_profile_id, container_size, reserved = PUBLIC_HEADER_STRUCT.unpack(
        data
    )

    if magic != MAGIC:
        raise ContainerFormatError("Vault magic bytes are invalid.")
    if version != FORMAT_VERSION:
        raise ContainerFormatError(f"Unsupported vault format version: {version}.")
    if reserved != RESERVED_BYTES:
        raise ContainerFormatError("Reserved public header bytes must be zeroed.")

    try:
        kdf_profile = KDF_PROFILE_NAMES[kdf_profile_id]
    except KeyError as exc:
        raise ContainerFormatError(f"Unknown KDF profile id: {kdf_profile_id}.") from exc

    return PublicHeader(
        version=version,
        flags=flags,
        kdf_profile=kdf_profile,
        container_size=container_size,
    )


def pack_index_size(size: int) -> bytes:
    """Pack an encrypted-index size field."""
    if not 0 <= size <= 0xFFFFFFFF:
        raise ContainerFormatError("Encrypted index size must fit in 4 bytes.")
    return struct.pack(">I", size)


def parse_index_size(data: bytes) -> int:
    """Parse a 4-byte encrypted-index size field."""
    if len(data) != INDEX_SIZE_BYTES:
        raise ContainerFormatError(
            f"Encrypted index size field must be exactly {INDEX_SIZE_BYTES} bytes."
        )
    return cast(int, struct.unpack(">I", data)[0])
