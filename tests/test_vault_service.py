"""Service-level tests for vault add/extract workflows."""

from hashlib import sha256
from pathlib import Path

import pytest

from vaultcli.errors import VaultFileNotFoundError
from vaultcli.vault import VaultService
from vaultcli.vault.vault import DEFAULT_CHUNK_SIZE


def _unexpected_unlock_failure(*args: object, **kwargs: object) -> object:
    raise AssertionError("Full unlock helper should not be used in this path.")


def test_vault_service_add_and_extract_round_trip(tmp_path: Path) -> None:
    vault_path = tmp_path / "service.vault"
    source_file = tmp_path / "secret.txt"
    source_file.write_text("hello from vault service", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="service-pass")
    added = VaultService.add_paths(vault_path, passphrase="service-pass", sources=[source_file])

    output_dir = tmp_path / "out"
    extracted = VaultService.extract_files(
        vault_path,
        passphrase="service-pass",
        output_dir=output_dir,
        internal_path="secret.txt",
    )

    assert len(added) == 1
    assert added[0].path == "secret.txt"
    assert len(extracted) == 1
    assert extracted[0].output_path.read_text(encoding="utf-8") == "hello from vault service"


def test_vault_service_extract_missing_file_raises(tmp_path: Path) -> None:
    vault_path = tmp_path / "service.vault"
    VaultService.create_empty_vault(vault_path, passphrase="service-pass")

    try:
        VaultService.extract_files(
            vault_path,
            passphrase="service-pass",
            output_dir=tmp_path / "out",
            internal_path="missing.txt",
        )
    except VaultFileNotFoundError:
        pass
    else:
        raise AssertionError("Expected missing internal path to raise VaultFileNotFoundError")


def test_vault_service_streams_multi_chunk_file_round_trip(tmp_path: Path) -> None:
    vault_path = tmp_path / "streamed.vault"
    source_file = tmp_path / "large.bin"
    expected = (b"chunked-data-" * 90_000) + b"tail"
    source_file.write_bytes(expected)

    VaultService.create_empty_vault(vault_path, passphrase="stream-passphrase")
    added = VaultService.add_paths(
        vault_path,
        passphrase="stream-passphrase",
        sources=[source_file],
    )
    extracted = VaultService.extract_files(
        vault_path,
        passphrase="stream-passphrase",
        output_dir=tmp_path / "out",
        internal_path="large.bin",
    )

    unlocked = VaultService._unlock(vault_path, passphrase="stream-passphrase")
    file_record = unlocked.index.files[0]

    assert added[0].original_size == len(expected)
    assert file_record.original_size == len(expected)
    assert len(file_record.chunks) > 1
    assert file_record.chunk_size == DEFAULT_CHUNK_SIZE
    assert sha256(extracted[0].output_path.read_bytes()).hexdigest() == sha256(expected).hexdigest()


def test_vault_service_appends_new_outer_file_after_existing_encrypted_data(tmp_path: Path) -> None:
    vault_path = tmp_path / "append.vault"
    first_file = tmp_path / "first.txt"
    second_file = tmp_path / "second.txt"
    first_file.write_text("alpha", encoding="utf-8")
    second_file.write_text("beta", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="append-passphrase")
    VaultService.add_paths(vault_path, passphrase="append-passphrase", sources=[first_file])
    before = VaultService._unlock(vault_path, passphrase="append-passphrase")
    first_record = before.index.files[0]
    prior_outer_length = len(before.outer_encrypted_data)

    VaultService.add_paths(vault_path, passphrase="append-passphrase", sources=[second_file])
    after = VaultService._unlock(vault_path, passphrase="append-passphrase")

    first_after = next(item for item in after.index.files if item.path == "first.txt")
    second_after = next(item for item in after.index.files if item.path == "second.txt")

    assert first_after.chunks == first_record.chunks
    assert second_after.chunks[0].offset >= prior_outer_length


def test_outer_authenticated_reads_do_not_require_full_unlock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_path = tmp_path / "metadata-only.vault"
    source_file = tmp_path / "secret.txt"
    source_file.write_text("metadata unlock path", encoding="utf-8")

    VaultService.create_empty_vault(vault_path, passphrase="metadata-passphrase")
    VaultService.add_paths(vault_path, passphrase="metadata-passphrase", sources=[source_file])

    monkeypatch.setattr(
        VaultService,
        "_unlock",
        classmethod(_unexpected_unlock_failure),
    )

    listed = VaultService.list_files(vault_path, passphrase="metadata-passphrase")
    info = VaultService.read_unlocked_info(vault_path, passphrase="metadata-passphrase")
    verified = VaultService.verify_unlocked(vault_path, passphrase="metadata-passphrase")
    extracted = VaultService.extract_files(
        vault_path,
        passphrase="metadata-passphrase",
        output_dir=tmp_path / "out",
        internal_path="secret.txt",
    )

    assert [item.path for item in listed] == ["secret.txt"]
    assert info.file_count == 1
    assert verified.checked_files == 1
    assert extracted[0].output_path.read_text(encoding="utf-8") == "metadata unlock path"
