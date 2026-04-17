"""Additional hardening tests for volume-index decoding."""

from __future__ import annotations

import random

import msgpack
import pytest

from vaultcli.container.index import VolumeIndex, deserialize_index, serialize_index
from vaultcli.errors import ContainerFormatError


def _valid_index_payload() -> dict[str, object]:
    return {
        "version": 1,
        "created_at": 1743000000,
        "reserved_tail_start": None,
        "files": [
            {
                "path": "docs/secret.txt",
                "original_size": 16,
                "encrypted_size": 32,
                "chunk_size": 8,
                "chunks": [
                    {
                        "nonce": b"1" * 12,
                        "offset": 0,
                        "ciphertext_size": 16,
                    }
                ],
                "added_at": 1743000001,
                "sha256": "abcd1234",
            }
        ],
    }


def test_deserialize_index_rejects_seeded_invalid_scalar_mutations() -> None:
    base_payload = _valid_index_payload()
    invalid_cases = (
        ("version", 2),
        ("version", "1"),
        ("created_at", -1),
        ("reserved_tail_start", -5),
        ("files", "not-a-list"),
    )

    for key, value in invalid_cases:
        mutated = dict(base_payload)
        mutated[key] = value
        payload = msgpack.packb(mutated, use_bin_type=True)
        with pytest.raises(ContainerFormatError):
            deserialize_index(payload)


def test_deserialize_index_rejects_seeded_invalid_file_record_mutations() -> None:
    base_payload = _valid_index_payload()
    invalid_files = (
        {
            "path": "",
            "original_size": 16,
            "encrypted_size": 32,
            "chunk_size": 8,
            "chunks": [],
            "added_at": 1,
            "sha256": "abcd",
        },
        {
            "path": "docs/secret.txt",
            "original_size": -1,
            "encrypted_size": 32,
            "chunk_size": 8,
            "chunks": [],
            "added_at": 1,
            "sha256": "abcd",
        },
        {
            "path": "docs/secret.txt",
            "original_size": 16,
            "encrypted_size": 32,
            "chunk_size": 0,
            "chunks": [],
            "added_at": 1,
            "sha256": "abcd",
        },
        {
            "path": "docs/secret.txt",
            "original_size": 16,
            "encrypted_size": 32,
            "chunk_size": 8,
            "chunks": "not-a-list",
            "added_at": 1,
            "sha256": "abcd",
        },
        {
            "path": "docs/secret.txt",
            "original_size": 16,
            "encrypted_size": 32,
            "chunk_size": 8,
            "chunks": [],
            "added_at": 1,
            "sha256": "",
        },
    )

    for invalid_file in invalid_files:
        mutated = dict(base_payload)
        mutated["files"] = [invalid_file]
        payload = msgpack.packb(mutated, use_bin_type=True)
        with pytest.raises(ContainerFormatError):
            deserialize_index(payload)


def test_deserialize_index_rejects_seeded_invalid_chunk_mutations() -> None:
    base_payload = _valid_index_payload()
    invalid_chunks = (
        {"nonce": b"", "offset": 0, "ciphertext_size": 16},
        {"nonce": b"1" * 12, "offset": -1, "ciphertext_size": 16},
        {"nonce": b"1" * 12, "offset": 0, "ciphertext_size": -2},
        {"nonce": "not-bytes", "offset": 0, "ciphertext_size": 16},
        "not-a-mapping",
    )

    for invalid_chunk in invalid_chunks:
        mutated = dict(base_payload)
        mutated["files"] = [
            {
                "path": "docs/secret.txt",
                "original_size": 16,
                "encrypted_size": 32,
                "chunk_size": 8,
                "chunks": [invalid_chunk],
                "added_at": 1743000001,
                "sha256": "abcd1234",
            }
        ]
        payload = msgpack.packb(mutated, use_bin_type=True)
        with pytest.raises(ContainerFormatError):
            deserialize_index(payload)


def test_deserialize_index_handles_seeded_byte_flips_without_crashing() -> None:
    base_index = VolumeIndex(
        version=1,
        created_at=1743000000,
        reserved_tail_start=4096,
        files=(),
    )
    payload = bytearray(serialize_index(base_index))
    rng = random.Random(20260418)
    mutation_offsets = sorted(
        {rng.randrange(0, len(payload)) for _ in range(min(12, len(payload)))}
    )

    for offset in mutation_offsets:
        mutated = bytearray(payload)
        mutated[offset] ^= 0x01
        try:
            decoded = deserialize_index(bytes(mutated))
        except ContainerFormatError:
            continue
        else:
            assert decoded.version == 1
            assert decoded.created_at >= 0


def test_deserialize_index_handles_seeded_truncations_without_crashing() -> None:
    base_index = VolumeIndex(
        version=1,
        created_at=1743000000,
        reserved_tail_start=None,
        files=(),
    )
    payload = serialize_index(base_index)
    truncation_points = {
        max(1, len(payload) - 1),
        max(1, len(payload) - 2),
        max(1, len(payload) // 2),
        1,
    }

    for size in truncation_points:
        truncated = payload[:size]
        try:
            decoded = deserialize_index(truncated)
        except ContainerFormatError:
            continue
        else:
            assert decoded.version == 1
            assert decoded.created_at >= 0
