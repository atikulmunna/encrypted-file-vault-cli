"""Tests for container reader/writer behavior."""

import random
from pathlib import Path

import pytest

from vaultcli.container.format import INDEX_DATA_OFFSET, INDEX_SIZE_OFFSET, PublicHeader
from vaultcli.container.reader import ContainerReader
from vaultcli.container.writer import (
    ContainerWriter,
    ContainerWriteRequest,
    EncryptedDataFileSegment,
)
from vaultcli.crypto.aes_gcm import EncryptedPayload
from vaultcli.crypto.kdf import KdfProfileName
from vaultcli.errors import ContainerFormatError


def _sample_request() -> ContainerWriteRequest:
    encrypted_index = b"encrypted-index"
    encrypted_data = b"encrypted-data-block"
    container_size = 32 + 32 + 12 + 48 + 4 + len(encrypted_index) + len(encrypted_data)

    return ContainerWriteRequest(
        header=PublicHeader(
            kdf_profile=KdfProfileName.INTERACTIVE,
            container_size=container_size,
        ),
        outer_salt=b"s" * 32,
        wrapped_dek=EncryptedPayload(
            nonce=b"n" * 12,
            ciphertext=b"c" * 48,
        ),
        encrypted_index=encrypted_index,
        encrypted_data=encrypted_data,
    )


def test_container_round_trip_bytes() -> None:
    request = _sample_request()

    payload = ContainerWriter.serialize_container(request)
    record = ContainerReader.read_bytes(payload)

    assert record.header == request.header
    assert record.outer_salt == request.outer_salt
    assert record.wrapped_dek == request.wrapped_dek
    assert record.encrypted_index == request.encrypted_index
    assert record.encrypted_data == request.encrypted_data


def test_container_iter_serialized_segments_matches_byte_serialization() -> None:
    request = _sample_request()

    payload = ContainerWriter.serialize_container(request)
    streamed_payload = b"".join(ContainerWriter.iter_serialized_segments(request))

    assert streamed_payload == payload


def test_container_supports_split_encrypted_data_segments() -> None:
    encrypted_index = b"encrypted-index"
    encrypted_parts = (b"outer-data", b"hidden-tail")
    request = ContainerWriteRequest(
        header=PublicHeader(
            kdf_profile=KdfProfileName.INTERACTIVE,
            container_size=32
            + 32
            + 12
            + 48
            + 4
            + len(encrypted_index)
            + sum(len(part) for part in encrypted_parts),
        ),
        outer_salt=b"s" * 32,
        wrapped_dek=EncryptedPayload(nonce=b"n" * 12, ciphertext=b"c" * 48),
        encrypted_index=encrypted_index,
        encrypted_data_segments=encrypted_parts,
    )

    payload = ContainerWriter.serialize_container(request)
    record = ContainerReader.read_bytes(payload)

    assert record.encrypted_index == encrypted_index
    assert record.encrypted_data == b"".join(encrypted_parts)


def test_container_read_rejects_header_size_mismatch() -> None:
    request = _sample_request()
    payload = bytearray(ContainerWriter.serialize_container(request))
    payload[12:20] = (1).to_bytes(8, "big")

    with pytest.raises(ContainerFormatError):
        ContainerReader.read_bytes(bytes(payload))


def test_container_read_rejects_truncated_index() -> None:
    request = _sample_request()
    payload = bytearray(ContainerWriter.serialize_container(request))
    payload[124:128] = (9999).to_bytes(4, "big")

    with pytest.raises(ContainerFormatError):
        ContainerReader.read_bytes(bytes(payload))


def test_container_writer_rejects_mismatched_container_size() -> None:
    request = _sample_request()
    broken = ContainerWriteRequest(
        header=PublicHeader(container_size=request.header.container_size + 1),
        outer_salt=request.outer_salt,
        wrapped_dek=request.wrapped_dek,
        encrypted_index=request.encrypted_index,
        encrypted_data=request.encrypted_data,
    )

    with pytest.raises(ContainerFormatError):
        ContainerWriter.serialize_container(broken)


def test_container_writer_rejects_dual_encrypted_data_inputs() -> None:
    request = ContainerWriteRequest(
        header=PublicHeader(container_size=32 + 32 + 12 + 48 + 4 + 1 + 1),
        outer_salt=b"s" * 32,
        wrapped_dek=EncryptedPayload(nonce=b"n" * 12, ciphertext=b"c" * 48),
        encrypted_index=b"i",
        encrypted_data=b"a",
        encrypted_data_segments=(b"b",),
    )

    with pytest.raises(ContainerFormatError):
        ContainerWriter.serialize_container(request)


def test_container_write_atomic_replaces_existing_file(tmp_path: Path) -> None:
    request = _sample_request()
    target = tmp_path / "sample.vault"
    target.write_bytes(b"old-data")

    written_path = ContainerWriter.write_atomic(target, request)
    record = ContainerReader.read_path(written_path)

    assert written_path == target
    assert target.read_bytes() != b"old-data"
    assert record.encrypted_index == request.encrypted_index


def test_container_read_path_round_trip(tmp_path: Path) -> None:
    request = _sample_request()
    target = tmp_path / "nested" / "sample.vault"

    ContainerWriter.write_atomic(target, request)
    record = ContainerReader.read_path(target)

    assert record.header.container_size == request.header.container_size


def test_container_read_path_metadata_skips_encrypted_payload_bytes(tmp_path: Path) -> None:
    request = _sample_request()
    target = tmp_path / "metadata.vault"

    ContainerWriter.write_atomic(target, request)
    metadata = ContainerReader.read_path_metadata(target)

    assert metadata.header == request.header
    assert metadata.outer_salt == request.outer_salt
    assert metadata.wrapped_dek == request.wrapped_dek
    assert metadata.encrypted_index == request.encrypted_index
    assert metadata.encrypted_data_size == len(request.encrypted_data)


def test_container_write_atomic_streams_large_encrypted_data(tmp_path: Path) -> None:
    encrypted_index = b"encrypted-index"
    encrypted_data = b"x" * (3 * 1024 * 1024 + 17)
    request = ContainerWriteRequest(
        header=PublicHeader(
            kdf_profile=KdfProfileName.INTERACTIVE,
            container_size=32 + 32 + 12 + 48 + 4 + len(encrypted_index) + len(encrypted_data),
        ),
        outer_salt=b"s" * 32,
        wrapped_dek=EncryptedPayload(nonce=b"n" * 12, ciphertext=b"c" * 48),
        encrypted_index=encrypted_index,
        encrypted_data=encrypted_data,
    )
    target = tmp_path / "large.vault"

    ContainerWriter.write_atomic(target, request)
    record = ContainerReader.read_path(target)

    assert record.encrypted_index == encrypted_index
    assert record.encrypted_data == encrypted_data


def test_container_write_atomic_supports_file_backed_encrypted_data_segment(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"prefix" + (b"x" * 256) + b"suffix")
    encrypted_index = b"encrypted-index"
    file_segment = EncryptedDataFileSegment(path=source, offset=6, length=256)
    request = ContainerWriteRequest(
        header=PublicHeader(
            kdf_profile=KdfProfileName.INTERACTIVE,
            container_size=32 + 32 + 12 + 48 + 4 + len(encrypted_index) + file_segment.length,
        ),
        outer_salt=b"s" * 32,
        wrapped_dek=EncryptedPayload(nonce=b"n" * 12, ciphertext=b"c" * 48),
        encrypted_index=encrypted_index,
        encrypted_data_segments=(file_segment,),
    )
    target = tmp_path / "file-backed.vault"

    ContainerWriter.write_atomic(target, request)
    record = ContainerReader.read_path(target)

    assert record.encrypted_index == encrypted_index
    assert record.encrypted_data == b"x" * 256


def test_container_read_rejects_seeded_reserved_header_mutations() -> None:
    request = _sample_request()
    payload = bytearray(ContainerWriter.serialize_container(request))
    rng = random.Random(20260415)

    # Reserved bytes occupy the last 12 bytes of the 32-byte public header.
    mutation_offsets = sorted({rng.randrange(20, 32) for _ in range(8)})

    for offset in mutation_offsets:
        mutated = bytearray(payload)
        mutated[offset] ^= 0x01
        with pytest.raises(ContainerFormatError):
            ContainerReader.read_bytes(bytes(mutated))


def test_container_read_rejects_seeded_oversized_index_lengths() -> None:
    request = _sample_request()
    payload = bytearray(ContainerWriter.serialize_container(request))
    rng = random.Random(20260416)

    for _ in range(8):
        mutated = bytearray(payload)
        oversized_index = len(payload) + rng.randrange(1, 50_000)
        mutated[INDEX_SIZE_OFFSET:INDEX_DATA_OFFSET] = oversized_index.to_bytes(4, "big")
        with pytest.raises(ContainerFormatError):
            ContainerReader.read_bytes(bytes(mutated))
