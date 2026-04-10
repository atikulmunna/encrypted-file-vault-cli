"""Hardening tests for malformed container and hidden-tail handling."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from vaultcli.errors import ContainerFormatError, CryptoAuthenticationError, HiddenVolumeError
from vaultcli.vault import VaultService


def test_verify_locked_rejects_multiple_truncation_points(tmp_path: Path) -> None:
    vault_path = tmp_path / "truncate.vault"
    source_file = tmp_path / "note.txt"
    source_file.write_text("truncate me", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="truncate-passphrase")
    VaultService.add_paths(vault_path, passphrase="truncate-passphrase", sources=[source_file])

    original = vault_path.read_bytes()
    truncation_sizes = {
        max(1, len(original) - 1),
        max(1, len(original) - 8),
        max(1, len(original) // 2),
        1,
    }

    for truncated_size in truncation_sizes:
        vault_path.write_bytes(original[:truncated_size])
        with pytest.raises(ContainerFormatError):
            VaultService.verify_locked(vault_path)


def test_verify_unlocked_rejects_seeded_bit_flips(tmp_path: Path) -> None:
    vault_path = tmp_path / "bitflip.vault"
    source_file = tmp_path / "secret.txt"
    source_file.write_text("bit flip target", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="bitflip-passphrase")
    VaultService.add_paths(vault_path, passphrase="bitflip-passphrase", sources=[source_file])

    original = vault_path.read_bytes()
    rng = random.Random(20260410)
    mutation_offsets = sorted(
        {
            rng.randrange(32, len(original))
            for _ in range(min(8, max(1, len(original) - 32)))
        }
    )

    for offset in mutation_offsets:
        mutated = bytearray(original)
        mutated[offset] ^= 0x01
        vault_path.write_bytes(bytes(mutated))
        with pytest.raises((ContainerFormatError, CryptoAuthenticationError, HiddenVolumeError)):
            VaultService.verify_unlocked(vault_path, passphrase="bitflip-passphrase")

    vault_path.write_bytes(original)


def test_hidden_list_rejects_corrupted_hidden_index_size(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-corrupt.vault"

    VaultService.create_empty_vault(vault_path, passphrase="OuterPassphrase123!")
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterPassphrase123!",
        inner_passphrase="InnerPassphrase123!",
        hidden_size=2048,
    )

    unlocked = VaultService._unlock(vault_path, passphrase="OuterPassphrase123!")
    assert unlocked.index.reserved_tail_start is not None

    payload = bytearray(vault_path.read_bytes())
    size_offset = unlocked.index.reserved_tail_start + 32 + 12 + 48
    payload[size_offset : size_offset + 4] = (10_000_000).to_bytes(4, "big")
    vault_path.write_bytes(bytes(payload))

    with pytest.raises(HiddenVolumeError):
        VaultService.list_hidden_files(
            vault_path,
            outer_passphrase="OuterPassphrase123!",
            inner_passphrase="InnerPassphrase123!",
        )
