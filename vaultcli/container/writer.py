"""Container writing helpers with atomic replace semantics."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tempfile

from vaultcli.container.format import (
    DEK_NONCE_BYTES,
    INDEX_DATA_OFFSET,
    OUTER_SALT_BYTES,
    WRAPPED_DEK_BYTES,
    PublicHeader,
    pack_index_size,
    pack_public_header,
)
from vaultcli.crypto.aes_gcm import EncryptedPayload
from vaultcli.errors import ContainerFormatError


@dataclass(frozen=True, slots=True)
class ContainerWriteRequest:
    """Structured payload needed to build a v1 outer-volume container."""

    header: PublicHeader
    outer_salt: bytes
    wrapped_dek: EncryptedPayload
    encrypted_index: bytes
    encrypted_data: bytes = b""


class ContainerWriter:
    """Write vault container bytes to disk safely."""

    @staticmethod
    def serialize_container(request: ContainerWriteRequest) -> bytes:
        """Serialize a validated container request into on-disk bytes."""
        _validate_write_request(request)

        index_size = pack_index_size(len(request.encrypted_index))
        body = b"".join(
            [
                pack_public_header(request.header),
                request.outer_salt,
                request.wrapped_dek.nonce,
                request.wrapped_dek.ciphertext,
                index_size,
                request.encrypted_index,
                request.encrypted_data,
            ]
        )

        if len(body) != request.header.container_size:
            raise ContainerFormatError(
                "Public header container_size does not match the serialized container length."
            )

        return body

    @classmethod
    def write_atomic(cls, path: str | Path, request: ContainerWriteRequest) -> Path:
        """Atomically write a container file by serializing to a temp file then replacing."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = cls.serialize_container(request)

        fd, temp_path_str = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
        )
        temp_path = Path(temp_path_str)

        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temp_path, target)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

        return target


def _validate_write_request(request: ContainerWriteRequest) -> None:
    if len(request.outer_salt) != OUTER_SALT_BYTES:
        raise ContainerFormatError(f"Outer salt must be exactly {OUTER_SALT_BYTES} bytes.")
    if len(request.wrapped_dek.nonce) != DEK_NONCE_BYTES:
        raise ContainerFormatError(f"Wrapped DEK nonce must be exactly {DEK_NONCE_BYTES} bytes.")
    if len(request.wrapped_dek.ciphertext) != WRAPPED_DEK_BYTES:
        raise ContainerFormatError(f"Wrapped DEK ciphertext must be exactly {WRAPPED_DEK_BYTES} bytes.")
    if not request.encrypted_index:
        raise ContainerFormatError("Encrypted index must not be empty.")
    if request.header.container_size < INDEX_DATA_OFFSET + len(request.encrypted_index):
        raise ContainerFormatError("Container size is too small for the required metadata layout.")
