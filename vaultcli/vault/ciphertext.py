"""Ciphertext sources and chunked file crypto helpers."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from vaultcli.container.index import ChunkRecord, FileRecord
from vaultcli.crypto.aes_gcm import EncryptedPayload, EncryptionService
from vaultcli.errors import ContainerFormatError

DEFAULT_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class InMemoryCiphertextSource:
    """Ciphertext backed by in-memory bytes."""

    data: bytes

    def read(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]


@dataclass(frozen=True, slots=True)
class FileCiphertextSource:
    """Ciphertext backed by a region inside a container file."""

    path: Path
    base_offset: int

    def read(self, offset: int, length: int) -> bytes:
        with self.path.open("rb") as handle:
            handle.seek(self.base_offset + offset)
            return handle.read(length)


CiphertextSource = InMemoryCiphertextSource | FileCiphertextSource


def encrypt_file_from_path(
    *,
    internal_path: str,
    source_path: Path,
    dek: bytes,
    encrypted_data: bytearray,
    base_offset: int = 0,
    added_at: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> FileRecord:
    """Encrypt a file into chunk records and append ciphertext to a buffer."""
    chunks: list[ChunkRecord] = []
    encrypted_size = 0
    original_size = 0
    digest = sha256()

    with source_path.open("rb") as handle:
        current_chunk = handle.read(chunk_size)
        chunk_index = 0

        if current_chunk == b"":
            payload = EncryptionService.encrypt_chunk(
                dek,
                b"",
                chunk_aad(internal_path, 0, True),
            )
            offset = base_offset + len(encrypted_data)
            encrypted_data.extend(payload.ciphertext)
            chunks.append(
                ChunkRecord(
                    nonce=payload.nonce,
                    offset=offset,
                    ciphertext_size=len(payload.ciphertext),
                )
            )
            encrypted_size += len(payload.ciphertext)
        else:
            while True:
                next_chunk = handle.read(chunk_size)
                is_final = next_chunk == b""
                original_size += len(current_chunk)
                digest.update(current_chunk)

                payload = EncryptionService.encrypt_chunk(
                    dek,
                    current_chunk,
                    chunk_aad(internal_path, chunk_index, is_final),
                )
                offset = base_offset + len(encrypted_data)
                encrypted_data.extend(payload.ciphertext)
                chunks.append(
                    ChunkRecord(
                        nonce=payload.nonce,
                        offset=offset,
                        ciphertext_size=len(payload.ciphertext),
                    )
                )
                encrypted_size += len(payload.ciphertext)

                if is_final:
                    break

                current_chunk = next_chunk
                chunk_index += 1

    return FileRecord(
        path=internal_path,
        original_size=original_size,
        encrypted_size=encrypted_size,
        chunk_size=chunk_size,
        chunks=tuple(chunks),
        added_at=added_at,
        sha256=digest.hexdigest(),
    )


def decrypt_file_to_path(
    file_record: FileRecord,
    ciphertext_source: CiphertextSource,
    dek: bytes,
    destination: Path,
) -> None:
    """Decrypt a file record to disk while verifying its digest."""
    digest = sha256()
    try:
        with destination.open("wb") as handle:
            for plaintext_chunk in iter_decrypted_chunks(file_record, ciphertext_source, dek):
                digest.update(plaintext_chunk)
                handle.write(plaintext_chunk)
    except Exception:
        if destination.exists():
            destination.unlink()
        raise

    if digest.hexdigest() != file_record.sha256:
        if destination.exists():
            destination.unlink()
        raise ContainerFormatError(f"SHA-256 mismatch while extracting {file_record.path}.")


def verify_file(file_record: FileRecord, ciphertext_source: CiphertextSource, dek: bytes) -> None:
    """Decrypt and hash a file record to verify integrity."""
    digest = sha256()
    for plaintext_chunk in iter_decrypted_chunks(file_record, ciphertext_source, dek):
        digest.update(plaintext_chunk)
    if digest.hexdigest() != file_record.sha256:
        raise ContainerFormatError(f"SHA-256 mismatch while verifying {file_record.path}.")


def iter_decrypted_chunks(
    file_record: FileRecord,
    ciphertext_source: CiphertextSource,
    dek: bytes,
) -> Iterator[bytes]:
    """Yield decrypted plaintext chunks for a file record."""
    for chunk_index, chunk in enumerate(file_record.chunks):
        ciphertext = ciphertext_source.read(chunk.offset, chunk.ciphertext_size)
        if len(ciphertext) != chunk.ciphertext_size:
            raise ContainerFormatError(
                f"Encrypted chunk for {file_record.path} is truncated at chunk {chunk_index}."
            )

        yield EncryptionService.decrypt_chunk(
            dek,
            EncryptedPayload(nonce=chunk.nonce, ciphertext=ciphertext),
            chunk_aad(
                file_record.path,
                chunk_index,
                chunk_index == len(file_record.chunks) - 1,
            ),
        )


def chunk_aad(internal_path: str, chunk_index: int, is_final: bool) -> bytes:
    """Build chunk AAD tied to the logical file path and position."""
    return f"{internal_path}|chunk={chunk_index}|final={int(is_final)}".encode()
