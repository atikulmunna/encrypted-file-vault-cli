"""Shared vault service models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vaultcli.container.index import VolumeIndex
from vaultcli.container.reader import ContainerMetadataRecord
from vaultcli.crypto.kdf import KdfProfileName
from vaultcli.vault.hidden import HiddenRegionMetadataRecord, UnlockedHiddenRegionMetadata


@dataclass(frozen=True, slots=True)
class LockedVaultInfo:
    """Metadata visible without decrypting the encrypted index."""

    path: Path
    format_version: int
    kdf_profile: KdfProfileName
    container_size: int


@dataclass(frozen=True, slots=True)
class UnlockedVaultInfo:
    """Authenticated metadata for the active volume."""

    path: Path
    active_volume: str
    format_version: int
    kdf_profile: KdfProfileName
    created_at: int
    file_count: int
    encrypted_size: int


@dataclass(frozen=True, slots=True)
class ListedVaultFile:
    """A single listed file entry."""

    path: str
    original_size: int
    added_at: int


@dataclass(frozen=True, slots=True)
class AddedVaultFile:
    """A single file added to a vault."""

    path: str
    original_size: int


@dataclass(frozen=True, slots=True)
class ExtractedVaultFile:
    """A single file extracted from a vault."""

    path: str
    output_path: Path
    original_size: int


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Result of a vault verification run."""

    mode: str
    active_volume: str | None
    status: str
    checked_files: int
    checked_chunks: int


@dataclass(frozen=True, slots=True)
class UnlockedVault:
    """Unlocked outer-volume material for compatibility and internal diagnostics."""

    path: Path
    record: ContainerMetadataRecord
    dek: bytes
    index: VolumeIndex
    outer_encrypted_data: bytes
    hidden_region: bytes


@dataclass(frozen=True, slots=True)
class MaterializedHiddenRegion:
    """Authenticated hidden-volume material with ciphertext bytes loaded."""

    record: HiddenRegionMetadataRecord
    dek: bytes
    index: VolumeIndex
    encrypted_data: bytes


@dataclass(frozen=True, slots=True)
class UnlockedHiddenVault:
    """Unlocked hidden-volume material plus the outer container context."""

    outer: UnlockedVault
    hidden: MaterializedHiddenRegion


@dataclass(frozen=True, slots=True)
class UnlockedVaultMetadata:
    """Unlocked outer-volume metadata without loading encrypted data bytes."""

    path: Path
    record: ContainerMetadataRecord
    dek: bytes
    index: VolumeIndex


@dataclass(frozen=True, slots=True)
class UnlockedHiddenVaultMetadata:
    """Unlocked hidden-volume metadata plus the outer container context."""

    outer: UnlockedVaultMetadata
    hidden: UnlockedHiddenRegionMetadata
