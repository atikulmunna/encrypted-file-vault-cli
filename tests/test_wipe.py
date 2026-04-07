"""Tests for the wipe service."""

from pathlib import Path

import pytest

from vaultcli.errors import WipeError
from vaultcli.wipe import wipe_file


def test_wipe_file_removes_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    target.write_text("wipe me", encoding="utf-8")

    wiped = wipe_file(target, passes=2)

    assert wiped == target
    assert not target.exists()


def test_wipe_file_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(WipeError):
        wipe_file(tmp_path / "missing.txt")


def test_wipe_file_rejects_non_positive_passes(tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    target.write_text("wipe me", encoding="utf-8")

    with pytest.raises(WipeError):
        wipe_file(target, passes=0)


def test_wipe_file_rejects_directory_target(tmp_path: Path) -> None:
    folder = tmp_path / "folder"
    folder.mkdir()

    with pytest.raises(WipeError):
        wipe_file(folder)
