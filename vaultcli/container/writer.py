"""Container writing helpers with atomic replace semantics."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

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
    encrypted_data_segments: tuple[bytes | EncryptedDataFileSegment, ...] = ()


@dataclass(frozen=True, slots=True)
class EncryptedDataFileSegment:
    """A slice of encrypted data copied directly from an existing container file."""

    path: Path
    offset: int
    length: int


class ContainerWriter:
    """Write vault container bytes to disk safely."""

    _WRITE_CHUNK_BYTES: Final[int] = 1024 * 1024

    @staticmethod
    def serialize_container(request: ContainerWriteRequest) -> bytes:
        """Serialize a validated container request into on-disk bytes."""
        _validate_write_request(request)
        if any(
            isinstance(segment, EncryptedDataFileSegment)
            for segment in request.encrypted_data_segments
        ):
            raise ContainerFormatError(
                "serialize_container does not support file-backed encrypted data segments."
            )
        body = b"".join(ContainerWriter.iter_serialized_segments(request))

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
        _validate_write_request(request)

        fd, temp_path_str = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
        )
        temp_path = Path(temp_path_str)

        try:
            with os.fdopen(fd, "wb") as handle:
                bytes_written = 0
                for segment in cls._iter_write_segments(request):
                    if isinstance(segment, bytes):
                        bytes_written += cls._write_segment(handle, segment)
                    else:
                        bytes_written += cls._write_file_segment(handle, segment)
                if bytes_written != request.header.container_size:
                    raise ContainerFormatError(
                        "Public header container_size does not match streamed write length."
                    )
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temp_path, target)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

        return target

    @staticmethod
    def _iter_write_segments(
        request: ContainerWriteRequest,
    ) -> Sequence[bytes | EncryptedDataFileSegment]:
        if request.encrypted_data_segments:
            encrypted_data_segments = request.encrypted_data_segments
        else:
            encrypted_data_segments = (request.encrypted_data,)

        segments: list[bytes | EncryptedDataFileSegment] = [
            pack_public_header(request.header),
            request.outer_salt,
            request.wrapped_dek.nonce,
            request.wrapped_dek.ciphertext,
            pack_index_size(len(request.encrypted_index)),
            request.encrypted_index,
        ]
        segments.extend(encrypted_data_segments)
        return segments

    @staticmethod
    def iter_serialized_segments(request: ContainerWriteRequest) -> tuple[bytes, ...]:
        """Yield the container layout as contiguous binary segments."""
        encrypted_data_segments = (
            request.encrypted_data_segments
            if request.encrypted_data_segments
            else (request.encrypted_data,)
        )
        segments = [
            pack_public_header(request.header),
            request.outer_salt,
            request.wrapped_dek.nonce,
            request.wrapped_dek.ciphertext,
            pack_index_size(len(request.encrypted_index)),
            request.encrypted_index,
        ]
        for segment in encrypted_data_segments:
            if not isinstance(segment, bytes):
                raise ContainerFormatError(
                    "iter_serialized_segments does not support file-backed encrypted data segments."
                )
            segments.append(segment)
        return tuple(segments)

    @classmethod
    def _write_segment(cls, handle: BinaryIO, segment: bytes) -> int:
        total = 0
        for start in range(0, len(segment), cls._WRITE_CHUNK_BYTES):
            chunk = segment[start : start + cls._WRITE_CHUNK_BYTES]
            if not chunk:
                continue
            handle.write(chunk)
            total += len(chunk)
        return total

    @classmethod
    def _write_file_segment(cls, handle: BinaryIO, segment: EncryptedDataFileSegment) -> int:
        total = 0
        with segment.path.open("rb") as source:
            source.seek(segment.offset)
            remaining = segment.length
            while remaining > 0:
                chunk = source.read(min(cls._WRITE_CHUNK_BYTES, remaining))
                if len(chunk) == 0:
                    raise ContainerFormatError(
                        "File-backed encrypted data segment ended before its declared length."
                    )
                handle.write(chunk)
                total += len(chunk)
                remaining -= len(chunk)
        return total


def _validate_write_request(request: ContainerWriteRequest) -> None:
    encrypted_sources = sum(
        1
        for is_used in (
            bool(request.encrypted_data),
            bool(request.encrypted_data_segments),
        )
        if is_used
    )
    if encrypted_sources > 1:
        raise ContainerFormatError(
            "Use exactly one encrypted data source: bytes, byte segments, or file segments."
        )
    if len(request.outer_salt) != OUTER_SALT_BYTES:
        raise ContainerFormatError(f"Outer salt must be exactly {OUTER_SALT_BYTES} bytes.")
    if len(request.wrapped_dek.nonce) != DEK_NONCE_BYTES:
        raise ContainerFormatError(f"Wrapped DEK nonce must be exactly {DEK_NONCE_BYTES} bytes.")
    if len(request.wrapped_dek.ciphertext) != WRAPPED_DEK_BYTES:
        raise ContainerFormatError(
            f"Wrapped DEK ciphertext must be exactly {WRAPPED_DEK_BYTES} bytes."
        )
    if not request.encrypted_index:
        raise ContainerFormatError("Encrypted index must not be empty.")
    encrypted_data_length = (
        sum(
            len(segment) if isinstance(segment, bytes) else segment.length
            for segment in request.encrypted_data_segments
        )
        if request.encrypted_data_segments
        else len(request.encrypted_data)
    )
    if request.header.container_size < INDEX_DATA_OFFSET + len(request.encrypted_index):
        raise ContainerFormatError("Container size is too small for the required metadata layout.")
    expected_size = INDEX_DATA_OFFSET + len(request.encrypted_index) + encrypted_data_length
    if request.header.container_size != expected_size:
        raise ContainerFormatError(
            "Public header container_size does not match the provided encrypted payload lengths."
        )
