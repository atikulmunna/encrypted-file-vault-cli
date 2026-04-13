"""Container reading helpers for the v1 outer-volume layout."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vaultcli.container.format import (
    INDEX_DATA_OFFSET,
    INDEX_SIZE_OFFSET,
    OUTER_DEK_NONCE_OFFSET,
    OUTER_SALT_OFFSET,
    WRAPPED_DEK_OFFSET,
    PublicHeader,
    parse_index_size,
    parse_public_header,
)
from vaultcli.crypto.aes_gcm import EncryptedPayload
from vaultcli.errors import ContainerFormatError


@dataclass(frozen=True, slots=True)
class ContainerRecord:
    """Parsed outer-volume container fields."""

    header: PublicHeader
    outer_salt: bytes
    wrapped_dek: EncryptedPayload
    encrypted_index: bytes
    encrypted_data_offset: int
    encrypted_data: bytes


@dataclass(frozen=True, slots=True)
class ContainerMetadataRecord:
    """Parsed outer-volume container fields without loading encrypted data bytes."""

    header: PublicHeader
    outer_salt: bytes
    wrapped_dek: EncryptedPayload
    encrypted_index: bytes
    encrypted_data_offset: int
    encrypted_data_size: int


class ContainerReader:
    """Read and validate a v1 outer-volume container from bytes or disk."""

    @staticmethod
    def read_bytes(data: bytes) -> ContainerRecord:
        """Parse a serialized container byte string."""
        if len(data) < INDEX_DATA_OFFSET:
            raise ContainerFormatError("Container is too small to contain the required metadata.")

        header = parse_public_header(data[:OUTER_SALT_OFFSET])
        if header.container_size != len(data):
            raise ContainerFormatError(
                "Container length does not match the public header container_size field."
            )

        outer_salt = data[OUTER_SALT_OFFSET:OUTER_DEK_NONCE_OFFSET]
        wrapped_dek_nonce = data[OUTER_DEK_NONCE_OFFSET:WRAPPED_DEK_OFFSET]
        wrapped_dek_ciphertext = data[WRAPPED_DEK_OFFSET:INDEX_SIZE_OFFSET]
        index_size = parse_index_size(data[INDEX_SIZE_OFFSET:INDEX_DATA_OFFSET])

        index_end = INDEX_DATA_OFFSET + index_size
        if index_end > len(data):
            raise ContainerFormatError("Encrypted index extends past the end of the container.")

        encrypted_index = data[INDEX_DATA_OFFSET:index_end]
        if not encrypted_index:
            raise ContainerFormatError("Encrypted index must not be empty.")

        encrypted_data = data[index_end:]

        return ContainerRecord(
            header=header,
            outer_salt=outer_salt,
            wrapped_dek=EncryptedPayload(
                nonce=wrapped_dek_nonce,
                ciphertext=wrapped_dek_ciphertext,
            ),
            encrypted_index=encrypted_index,
            encrypted_data_offset=index_end,
            encrypted_data=encrypted_data,
        )

    @classmethod
    def read_path(cls, path: str | Path) -> ContainerRecord:
        """Read and parse a serialized container from disk."""
        payload = Path(path).read_bytes()
        return cls.read_bytes(payload)

    @staticmethod
    def read_path_metadata(path: str | Path) -> ContainerMetadataRecord:
        """Read only the header and encrypted index from disk."""
        target = Path(path)
        with target.open("rb") as handle:
            prefix = handle.read(INDEX_DATA_OFFSET)
            if len(prefix) < INDEX_DATA_OFFSET:
                raise ContainerFormatError(
                    "Container is too small to contain the required metadata."
                )

            header = parse_public_header(prefix[:OUTER_SALT_OFFSET])
            outer_salt = prefix[OUTER_SALT_OFFSET:OUTER_DEK_NONCE_OFFSET]
            wrapped_dek_nonce = prefix[OUTER_DEK_NONCE_OFFSET:WRAPPED_DEK_OFFSET]
            wrapped_dek_ciphertext = prefix[WRAPPED_DEK_OFFSET:INDEX_SIZE_OFFSET]
            index_size = parse_index_size(prefix[INDEX_SIZE_OFFSET:INDEX_DATA_OFFSET])
            encrypted_index = handle.read(index_size)
            if len(encrypted_index) != index_size:
                raise ContainerFormatError(
                    "Encrypted index extends past the end of the container."
                )

            encrypted_data_offset = INDEX_DATA_OFFSET + index_size
            if header.container_size < encrypted_data_offset:
                raise ContainerFormatError(
                    "Container length does not match the public header container_size field."
                )

            return ContainerMetadataRecord(
                header=header,
                outer_salt=outer_salt,
                wrapped_dek=EncryptedPayload(
                    nonce=wrapped_dek_nonce,
                    ciphertext=wrapped_dek_ciphertext,
                ),
                encrypted_index=encrypted_index,
                encrypted_data_offset=encrypted_data_offset,
                encrypted_data_size=header.container_size - encrypted_data_offset,
            )
