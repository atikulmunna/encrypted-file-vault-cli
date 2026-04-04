"""Tests for volume-index serialization helpers."""

import msgpack
import pytest

from vaultcli.container.index import (
    ChunkRecord,
    FileRecord,
    VolumeIndex,
    deserialize_index,
    serialize_index,
)
from vaultcli.errors import ContainerFormatError


def test_volume_index_round_trip() -> None:
    index = VolumeIndex(
        version=1,
        created_at=1743000000,
        reserved_tail_start=52428800,
        files=(
            FileRecord(
                path="documents/secret.txt",
                original_size=4096,
                encrypted_size=4208,
                chunk_size=1048576,
                chunks=(ChunkRecord(nonce=b"1" * 12, offset=1024, ciphertext_size=4112),),
                added_at=1743000100,
                sha256="abc123",
            ),
        ),
    )

    encoded = serialize_index(index)
    decoded = deserialize_index(encoded)

    assert decoded == index


def test_deserialize_index_rejects_non_mapping_payload() -> None:
    payload = msgpack.packb(["not", "a", "mapping"], use_bin_type=True)

    with pytest.raises(ContainerFormatError):
        deserialize_index(payload)


def test_deserialize_index_rejects_missing_files_list() -> None:
    payload = msgpack.packb({"version": 1, "created_at": 1}, use_bin_type=True)

    with pytest.raises(ContainerFormatError):
        deserialize_index(payload)


def test_deserialize_index_rejects_invalid_chunk_nonce() -> None:
    payload = msgpack.packb(
        {
            "version": 1,
            "created_at": 1,
            "reserved_tail_start": None,
            "files": [
                {
                    "path": "bad.txt",
                    "original_size": 1,
                    "encrypted_size": 2,
                    "chunk_size": 1,
                    "chunks": [{"nonce": "", "offset": 0, "ciphertext_size": 2}],
                    "added_at": 1,
                    "sha256": "deadbeef",
                }
            ],
        },
        use_bin_type=True,
    )

    with pytest.raises(ContainerFormatError):
        deserialize_index(payload)
