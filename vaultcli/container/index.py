"""Encrypted volume-index schema and msgpack serialization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import msgpack

from vaultcli.errors import ContainerFormatError

INDEX_VERSION = 1


@dataclass(frozen=True, slots=True)
class ChunkRecord:
    """Metadata for one encrypted chunk."""

    nonce: bytes
    offset: int
    ciphertext_size: int


@dataclass(frozen=True, slots=True)
class FileRecord:
    """Metadata for one encrypted file."""

    path: str
    original_size: int
    encrypted_size: int
    chunk_size: int
    chunks: tuple[ChunkRecord, ...]
    added_at: int
    sha256: str


@dataclass(frozen=True, slots=True)
class VolumeIndex:
    """Decrypted metadata index for one volume."""

    version: int
    created_at: int
    reserved_tail_start: int | None
    files: tuple[FileRecord, ...]


def serialize_index(index: VolumeIndex) -> bytes:
    """Serialize a validated volume index to msgpack bytes."""
    _validate_volume_index(index)

    payload = {
        "version": index.version,
        "created_at": index.created_at,
        "reserved_tail_start": index.reserved_tail_start,
        "files": [
            {
                "path": file.path,
                "original_size": file.original_size,
                "encrypted_size": file.encrypted_size,
                "chunk_size": file.chunk_size,
                "chunks": [
                    {
                        "nonce": chunk.nonce,
                        "offset": chunk.offset,
                        "ciphertext_size": chunk.ciphertext_size,
                    }
                    for chunk in file.chunks
                ],
                "added_at": file.added_at,
                "sha256": file.sha256,
            }
            for file in index.files
        ],
    }

    return cast(bytes, msgpack.packb(payload, use_bin_type=True))


def deserialize_index(data: bytes) -> VolumeIndex:
    """Deserialize and validate a msgpack-encoded volume index."""
    try:
        payload = msgpack.unpackb(data, raw=False)
    except (ValueError, msgpack.ExtraData, msgpack.FormatError, msgpack.StackError) as exc:
        raise ContainerFormatError("Encrypted index payload is not valid msgpack.") from exc

    if not isinstance(payload, dict):
        raise ContainerFormatError("Volume index must decode to a mapping.")

    version = _require_int(payload, "version")
    if version != INDEX_VERSION:
        raise ContainerFormatError(f"Unsupported volume-index version: {version}.")

    created_at = _require_non_negative_int(payload, "created_at")
    reserved_tail_start = payload.get("reserved_tail_start")
    if reserved_tail_start is not None and (
        not isinstance(reserved_tail_start, int) or reserved_tail_start < 0
    ):
        raise ContainerFormatError("reserved_tail_start must be null or a non-negative integer.")

    files_raw = payload.get("files")
    if not isinstance(files_raw, list):
        raise ContainerFormatError("files must be a list.")

    files = tuple(_parse_file_record(item) for item in files_raw)

    return VolumeIndex(
        version=version,
        created_at=created_at,
        reserved_tail_start=reserved_tail_start,
        files=files,
    )


def _parse_file_record(item: object) -> FileRecord:
    if not isinstance(item, dict):
        raise ContainerFormatError("Each file record must be a mapping.")

    path = item.get("path")
    sha256 = item.get("sha256")
    if not isinstance(path, str) or not path:
        raise ContainerFormatError("File path must be a non-empty string.")
    if not isinstance(sha256, str) or not sha256:
        raise ContainerFormatError("sha256 must be a non-empty string.")

    chunks_raw = item.get("chunks")
    if not isinstance(chunks_raw, list):
        raise ContainerFormatError("chunks must be a list.")

    chunks = tuple(_parse_chunk_record(chunk) for chunk in chunks_raw)

    return FileRecord(
        path=path,
        original_size=_require_non_negative_int(item, "original_size"),
        encrypted_size=_require_non_negative_int(item, "encrypted_size"),
        chunk_size=_require_positive_int(item, "chunk_size"),
        chunks=chunks,
        added_at=_require_non_negative_int(item, "added_at"),
        sha256=sha256,
    )


def _parse_chunk_record(item: object) -> ChunkRecord:
    if not isinstance(item, dict):
        raise ContainerFormatError("Each chunk record must be a mapping.")

    nonce = item.get("nonce")
    if not isinstance(nonce, bytes) or not nonce:
        raise ContainerFormatError("Chunk nonce must be non-empty bytes.")

    return ChunkRecord(
        nonce=nonce,
        offset=_require_non_negative_int(item, "offset"),
        ciphertext_size=_require_non_negative_int(item, "ciphertext_size"),
    )


def _validate_volume_index(index: VolumeIndex) -> None:
    if index.version != INDEX_VERSION:
        raise ContainerFormatError(f"Unsupported volume-index version: {index.version}.")
    if index.created_at < 0:
        raise ContainerFormatError("created_at must be non-negative.")
    if index.reserved_tail_start is not None and index.reserved_tail_start < 0:
        raise ContainerFormatError("reserved_tail_start must be non-negative when present.")

    for file in index.files:
        if not file.path:
            raise ContainerFormatError("File path must be non-empty.")
        if file.original_size < 0 or file.encrypted_size < 0 or file.added_at < 0:
            raise ContainerFormatError("File sizes and timestamps must be non-negative.")
        if file.chunk_size <= 0:
            raise ContainerFormatError("chunk_size must be positive.")
        if not file.sha256:
            raise ContainerFormatError("sha256 must be non-empty.")

        for chunk in file.chunks:
            if not chunk.nonce:
                raise ContainerFormatError("Chunk nonce must be non-empty.")
            if chunk.offset < 0 or chunk.ciphertext_size < 0:
                raise ContainerFormatError("Chunk offsets and sizes must be non-negative.")


def _require_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int):
        raise ContainerFormatError(f"{key} must be an integer.")
    return value


def _require_non_negative_int(mapping: dict[str, object], key: str) -> int:
    value = _require_int(mapping, key)
    if value < 0:
        raise ContainerFormatError(f"{key} must be non-negative.")
    return value


def _require_positive_int(mapping: dict[str, object], key: str) -> int:
    value = _require_int(mapping, key)
    if value <= 0:
        raise ContainerFormatError(f"{key} must be positive.")
    return value
