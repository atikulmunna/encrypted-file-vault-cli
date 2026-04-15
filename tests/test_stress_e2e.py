"""Larger end-to-end workflow coverage for outer and hidden volumes."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from vaultcli.vault import VaultService


def _build_source_tree(root: Path, *, prefix: str) -> list[tuple[str, bytes]]:
    fixtures = [
        (f"{prefix}/root.txt", b"root-data"),
        (f"{prefix}/docs/readme.md", b"# readme\ncontent\n"),
        (f"{prefix}/docs/deep/spec.txt", b"specification-data"),
        (f"{prefix}/bin/blob.bin", (b"blob-" * 250_000) + b"tail"),
    ]
    for relative_path, payload in fixtures:
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return fixtures


def test_outer_volume_round_trips_large_directory_tree(tmp_path: Path) -> None:
    vault_path = tmp_path / "outer-stress.vault"
    source_root = tmp_path / "outer-source"
    extracted_root = tmp_path / "outer-out"
    fixtures = _build_source_tree(source_root, prefix="dataset")

    VaultService.create_empty_vault(vault_path, passphrase="OuterStressPassphrase123!")
    added = VaultService.add_paths(
        vault_path,
        passphrase="OuterStressPassphrase123!",
        sources=[source_root / "dataset"],
    )
    listed = VaultService.list_files(vault_path, passphrase="OuterStressPassphrase123!")
    extracted = VaultService.extract_files(
        vault_path,
        passphrase="OuterStressPassphrase123!",
        output_dir=extracted_root,
        extract_all=True,
        overwrite=True,
    )
    verified = VaultService.verify_unlocked(
        vault_path,
        passphrase="OuterStressPassphrase123!",
    )

    assert len(added) == len(fixtures)
    assert len(listed) == len(fixtures)
    assert len(extracted) == len(fixtures)
    assert verified.checked_files == len(fixtures)

    for relative_path, payload in fixtures:
        extracted_path = extracted_root / relative_path
        assert extracted_path.exists()
        assert sha256(extracted_path.read_bytes()).hexdigest() == sha256(payload).hexdigest()


def test_outer_and_hidden_volumes_stay_isolated_under_stress(tmp_path: Path) -> None:
    vault_path = tmp_path / "hidden-stress.vault"
    outer_root = tmp_path / "outer-source"
    hidden_root = tmp_path / "hidden-source"
    outer_out = tmp_path / "outer-out"
    hidden_out = tmp_path / "hidden-out"
    outer_fixtures = _build_source_tree(outer_root, prefix="outerset")
    hidden_fixtures = _build_source_tree(hidden_root, prefix="hiddenset")

    VaultService.create_empty_vault(vault_path, passphrase="OuterStressPassphrase123!")
    VaultService.add_paths(
        vault_path,
        passphrase="OuterStressPassphrase123!",
        sources=[outer_root / "outerset"],
    )
    VaultService.create_hidden_volume(
        vault_path,
        outer_passphrase="OuterStressPassphrase123!",
        inner_passphrase="InnerStressPassphrase123!",
        hidden_size=3 * 1024 * 1024,
    )
    VaultService.add_hidden_paths(
        vault_path,
        outer_passphrase="OuterStressPassphrase123!",
        inner_passphrase="InnerStressPassphrase123!",
        sources=[hidden_root / "hiddenset"],
    )

    outer_listed = VaultService.list_files(vault_path, passphrase="OuterStressPassphrase123!")
    hidden_listed = VaultService.list_hidden_files(
        vault_path,
        outer_passphrase="OuterStressPassphrase123!",
        inner_passphrase="InnerStressPassphrase123!",
    )
    outer_extracted = VaultService.extract_files(
        vault_path,
        passphrase="OuterStressPassphrase123!",
        output_dir=outer_out,
        extract_all=True,
        overwrite=True,
    )
    hidden_extracted = VaultService.extract_hidden_files(
        vault_path,
        outer_passphrase="OuterStressPassphrase123!",
        inner_passphrase="InnerStressPassphrase123!",
        output_dir=hidden_out,
        extract_all=True,
        overwrite=True,
    )
    outer_verified = VaultService.verify_unlocked(
        vault_path,
        passphrase="OuterStressPassphrase123!",
    )
    hidden_verified = VaultService.verify_hidden(
        vault_path,
        outer_passphrase="OuterStressPassphrase123!",
        inner_passphrase="InnerStressPassphrase123!",
    )

    assert len(outer_listed) == len(outer_fixtures)
    assert len(hidden_listed) == len(hidden_fixtures)
    assert len(outer_extracted) == len(outer_fixtures)
    assert len(hidden_extracted) == len(hidden_fixtures)
    assert outer_verified.checked_files == len(outer_fixtures)
    assert hidden_verified.checked_files == len(hidden_fixtures)

    for relative_path, payload in outer_fixtures:
        extracted_path = outer_out / relative_path
        assert sha256(extracted_path.read_bytes()).hexdigest() == sha256(payload).hexdigest()

    for relative_path, payload in hidden_fixtures:
        extracted_path = hidden_out / relative_path
        assert sha256(extracted_path.read_bytes()).hexdigest() == sha256(payload).hexdigest()

    assert [item.path for item in outer_listed] != [item.path for item in hidden_listed]
