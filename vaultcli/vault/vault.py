"""High-level outer-volume operations for the current VaultCLI slice."""

from __future__ import annotations

import secrets
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from vaultcli.container.format import PublicHeader, pack_public_header
from vaultcli.container.index import (
    FileRecord,
    VolumeIndex,
    deserialize_index,
    serialize_index,
)
from vaultcli.container.reader import ContainerMetadataRecord, ContainerReader
from vaultcli.container.writer import (
    ContainerWriter,
    ContainerWriteRequest,
    EncryptedDataFileSegment,
)
from vaultcli.crypto.aes_gcm import AES256_KEY_BYTES, EncryptedPayload, EncryptionService
from vaultcli.crypto.kdf import KdfProfileName, KdfService
from vaultcli.errors import (
    ContainerFormatError,
    CryptoAuthenticationError,
    HiddenVolumeError,
    VaultFileNotFoundError,
)
from vaultcli.passphrases import enforce_passphrase_policy
from vaultcli.vault.ciphertext import (
    DEFAULT_CHUNK_SIZE as CHUNK_SIZE_DEFAULT,
)
from vaultcli.vault.ciphertext import (
    CiphertextSource,
    FileCiphertextSource,
    InMemoryCiphertextSource,
    decrypt_file_to_path,
    encrypt_file_from_path,
    verify_file,
)
from vaultcli.vault.hidden import (
    build_hidden_region,
    serialize_hidden_region_prefix,
    unlock_hidden_region_metadata,
)
from vaultcli.vault.models import (
    AddedVaultFile,
    ExtractedVaultFile,
    ListedVaultFile,
    LockedVaultInfo,
    MaterializedHiddenRegion,
    UnlockedHiddenVault,
    UnlockedHiddenVaultMetadata,
    UnlockedVault,
    UnlockedVaultInfo,
    UnlockedVaultMetadata,
    VerificationResult,
)

INDEX_AAD: Final[bytes] = b"vaultcli:outer-index"
DEFAULT_CHUNK_SIZE: Final[int] = CHUNK_SIZE_DEFAULT


class VaultService:
    """Current outer-volume service used by the first real CLI commands."""

    @classmethod
    def create_empty_vault(
        cls,
        path: str | Path,
        *,
        passphrase: str,
        kdf_profile: KdfProfileName = KdfProfileName.INTERACTIVE,
        allow_weak_passphrase: bool = False,
    ) -> Path:
        """Create an empty outer-volume vault and write it atomically."""
        enforce_passphrase_policy(passphrase, allow_weak=allow_weak_passphrase)
        created_at = int(time.time())
        index = VolumeIndex(
            version=1,
            created_at=created_at,
            reserved_tail_start=None,
            files=(),
        )
        encrypted_data = b""
        outer_salt = secrets.token_bytes(32)
        header = PublicHeader(kdf_profile=kdf_profile, container_size=0)
        header_bytes = pack_public_header(header)

        kek = KdfService.derive_key(passphrase, outer_salt, kdf_profile)
        dek = EncryptionService.generate_dek()
        wrapped_dek = EncryptionService.wrap_dek(kek, dek, header_bytes)
        encrypted_index = cls._encrypt_index(index, dek)

        final_header = PublicHeader(
            kdf_profile=kdf_profile,
            container_size=32 + 32 + 12 + 48 + 4 + len(encrypted_index) + len(encrypted_data),
        )
        final_header_bytes = pack_public_header(final_header)
        final_wrapped_dek = EncryptionService.wrap_dek(
            kek,
            dek,
            final_header_bytes,
            nonce=wrapped_dek.nonce,
        )

        request = ContainerWriteRequest(
            header=final_header,
            outer_salt=outer_salt,
            wrapped_dek=final_wrapped_dek,
            encrypted_index=encrypted_index,
            encrypted_data=encrypted_data,
        )
        return ContainerWriter.write_atomic(path, request)

    @classmethod
    def rekey_vault(
        cls,
        vault_path: str | Path,
        *,
        current_passphrase: str,
        new_passphrase: str,
        allow_weak_passphrase: bool = False,
    ) -> Path:
        """Re-wrap the existing DEK with a KEK derived from a new passphrase."""
        enforce_passphrase_policy(new_passphrase, allow_weak=allow_weak_passphrase)
        unlocked = cls._unlock_outer_metadata(Path(vault_path), passphrase=current_passphrase)
        return cls._write_updated_vault_from_segments(
            unlocked,
            passphrase=new_passphrase,
            index=unlocked.index,
            encrypted_data_segments=cls._existing_encrypted_file_segments(unlocked),
            outer_encrypted_length=cls._existing_outer_encrypted_length(unlocked),
        )

    @classmethod
    def create_hidden_volume(
        cls,
        vault_path: str | Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
        hidden_size: int,
        allow_weak_passphrase: bool = False,
    ) -> Path:
        """Append a hidden-volume region and reserve the tail for outer writes."""
        enforce_passphrase_policy(inner_passphrase, allow_weak=allow_weak_passphrase)
        unlocked = cls._unlock_outer_metadata(Path(vault_path), passphrase=outer_passphrase)
        if unlocked.index.reserved_tail_start is not None:
            raise HiddenVolumeError("Hidden volume already configured for this vault.")

        hidden_region = build_hidden_region(
            passphrase=inner_passphrase,
            kdf_profile=unlocked.record.header.kdf_profile,
            hidden_size=hidden_size,
        )
        new_index = VolumeIndex(
            version=unlocked.index.version,
            created_at=unlocked.index.created_at,
            reserved_tail_start=0,
            files=unlocked.index.files,
        )
        return cls._write_updated_vault_from_segments(
            unlocked,
            passphrase=outer_passphrase,
            index=new_index,
            encrypted_data_segments=(
                *cls._existing_encrypted_file_segments(unlocked, include_hidden=False),
                hidden_region,
            ),
            outer_encrypted_length=cls._existing_outer_encrypted_length(unlocked),
        )

    @classmethod
    def add_paths(
        cls,
        vault_path: str | Path,
        *,
        passphrase: str,
        sources: Sequence[str | Path],
    ) -> list[AddedVaultFile]:
        """Encrypt and add one or more source files/directories to the outer volume."""
        unlocked = cls._unlock_outer_metadata(Path(vault_path), passphrase=passphrase)
        outer_encrypted_length = cls._existing_outer_encrypted_length(unlocked)
        encrypted_data = bytearray()
        files_by_path = {file.path: file for file in unlocked.index.files}
        added_files: list[AddedVaultFile] = []
        now = int(time.time())

        for source in sources:
            for internal_path, source_path in _iter_source_files(Path(source)):
                file_record = encrypt_file_from_path(
                    internal_path=internal_path,
                    source_path=source_path,
                    dek=unlocked.dek,
                    encrypted_data=encrypted_data,
                    base_offset=outer_encrypted_length,
                    added_at=now,
                )
                files_by_path[internal_path] = file_record
                added_files.append(
                    AddedVaultFile(path=internal_path, original_size=file_record.original_size)
                )

        new_index = VolumeIndex(
            version=unlocked.index.version,
            created_at=unlocked.index.created_at,
            reserved_tail_start=unlocked.index.reserved_tail_start,
            files=tuple(sorted(files_by_path.values(), key=lambda item: item.path)),
        )
        cls._write_updated_vault_from_segments(
            unlocked,
            passphrase=passphrase,
            index=new_index,
            encrypted_data_segments=(
                *cls._existing_encrypted_file_segments(unlocked, include_hidden=False),
                bytes(encrypted_data),
                *cls._existing_hidden_file_segments(unlocked),
            ),
            outer_encrypted_length=outer_encrypted_length + len(encrypted_data),
        )
        return added_files

    @classmethod
    def add_hidden_paths(
        cls,
        vault_path: str | Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
        sources: Sequence[str | Path],
    ) -> list[AddedVaultFile]:
        """Encrypt and add files or directories to the hidden volume."""
        unlocked = cls._unlock_hidden_state(
            Path(vault_path),
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )
        existing_hidden_length = cls._existing_hidden_encrypted_length(unlocked)
        encrypted_data = bytearray()
        files_by_path = {file.path: file for file in unlocked.hidden.index.files}
        added_files: list[AddedVaultFile] = []
        now = int(time.time())

        for source in sources:
            for internal_path, source_path in _iter_source_files(Path(source)):
                file_record = encrypt_file_from_path(
                    internal_path=internal_path,
                    source_path=source_path,
                    dek=unlocked.hidden.dek,
                    encrypted_data=encrypted_data,
                    base_offset=existing_hidden_length,
                    added_at=now,
                )
                files_by_path[internal_path] = file_record
                added_files.append(
                    AddedVaultFile(path=internal_path, original_size=file_record.original_size)
                )

        created_at = unlocked.hidden.index.created_at or now
        new_index = VolumeIndex(
            version=unlocked.hidden.index.version,
            created_at=created_at,
            reserved_tail_start=None,
            files=tuple(sorted(files_by_path.values(), key=lambda item: item.path)),
        )
        cls._write_updated_hidden_volume_from_segments(
            unlocked,
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
            index=new_index,
            hidden_encrypted_data_segments=(
                *cls._existing_hidden_encrypted_file_segments(unlocked),
                bytes(encrypted_data),
            ),
            hidden_encrypted_length=existing_hidden_length + len(encrypted_data),
        )
        return added_files

    @classmethod
    def extract_files(
        cls,
        vault_path: str | Path,
        *,
        passphrase: str,
        output_dir: str | Path,
        internal_path: str | None = None,
        extract_all: bool = False,
        overwrite: bool = False,
    ) -> list[ExtractedVaultFile]:
        """Decrypt one or all files from the outer volume to disk."""
        if not extract_all and internal_path is None:
            raise ContainerFormatError(
                "Choose an internal path to extract, or pass --all to extract the full vault."
            )

        unlocked = cls._unlock_outer_metadata(Path(vault_path), passphrase=passphrase)
        ciphertext_source = cls._outer_ciphertext_source(unlocked)
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        if extract_all:
            selected = list(unlocked.index.files)
        else:
            selected = [cls._get_file_record(unlocked.index, internal_path or "")]

        extracted: list[ExtractedVaultFile] = []
        for file_record in selected:
            destination = target_dir / Path(file_record.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and not overwrite:
                raise ContainerFormatError(
                    f"Refusing to overwrite existing file: {destination}. "
                    "Pass --overwrite if you want to replace it."
                )
            decrypt_file_to_path(
                file_record,
                ciphertext_source,
                unlocked.dek,
                destination,
            )
            extracted.append(
                ExtractedVaultFile(
                    path=file_record.path,
                    output_path=destination,
                    original_size=file_record.original_size,
                )
            )

        return extracted

    @classmethod
    def extract_hidden_files(
        cls,
        vault_path: str | Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
        output_dir: str | Path,
        internal_path: str | None = None,
        extract_all: bool = False,
        overwrite: bool = False,
    ) -> list[ExtractedVaultFile]:
        """Decrypt one or all files from the hidden volume to disk."""
        if not extract_all and internal_path is None:
            raise ContainerFormatError(
                "Choose an internal path to extract, or pass --all to extract "
                "the full hidden volume."
            )

        unlocked = cls._unlock_hidden_state(
            Path(vault_path),
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )
        ciphertext_source = cls._hidden_ciphertext_source(unlocked)
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        if extract_all:
            selected = list(unlocked.hidden.index.files)
        else:
            selected = [cls._get_file_record(unlocked.hidden.index, internal_path or "")]

        extracted: list[ExtractedVaultFile] = []
        for file_record in selected:
            destination = target_dir / Path(file_record.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and not overwrite:
                raise ContainerFormatError(
                    f"Refusing to overwrite existing file: {destination}. "
                    "Pass --overwrite if you want to replace it."
                )
            decrypt_file_to_path(
                file_record,
                ciphertext_source,
                unlocked.hidden.dek,
                destination,
            )
            extracted.append(
                ExtractedVaultFile(
                    path=file_record.path,
                    output_path=destination,
                    original_size=file_record.original_size,
                )
            )

        return extracted

    @classmethod
    def verify_locked(cls, path: str | Path) -> VerificationResult:
        """Perform a structural-only verification without authenticating ciphertext."""
        record = ContainerReader.read_path(path)
        if len(record.encrypted_index) <= 12:
            raise ContainerFormatError("Encrypted index payload is too small to contain a nonce.")

        return VerificationResult(
            mode="locked",
            active_volume=None,
            status="verified",
            checked_files=0,
            checked_chunks=0,
        )

    @classmethod
    def verify_unlocked(cls, path: str | Path, *, passphrase: str) -> VerificationResult:
        """Perform authenticated verification of the active outer volume."""
        unlocked = cls._unlock_outer_metadata(Path(path), passphrase=passphrase)
        ciphertext_source = cls._outer_ciphertext_source(unlocked)
        checked_chunks = 0

        for file_record in unlocked.index.files:
            verify_file(file_record, ciphertext_source, unlocked.dek)
            checked_chunks += len(file_record.chunks)

        return VerificationResult(
            mode="unlocked",
            active_volume="outer",
            status="verified",
            checked_files=len(unlocked.index.files),
            checked_chunks=checked_chunks,
        )

    @classmethod
    def verify_hidden(
        cls,
        path: str | Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> VerificationResult:
        """Perform authenticated verification of the hidden volume."""
        unlocked = cls._unlock_hidden_state(
            Path(path),
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )
        ciphertext_source = cls._hidden_ciphertext_source(unlocked)
        checked_chunks = 0

        for file_record in unlocked.hidden.index.files:
            verify_file(file_record, ciphertext_source, unlocked.hidden.dek)
            checked_chunks += len(file_record.chunks)

        return VerificationResult(
            mode="unlocked",
            active_volume="hidden",
            status="verified",
            checked_files=len(unlocked.hidden.index.files),
            checked_chunks=checked_chunks,
        )

    @classmethod
    def read_locked_info(cls, path: str | Path) -> LockedVaultInfo:
        """Read public header metadata without decrypting the encrypted index."""
        target = Path(path)
        record = ContainerReader.read_path_metadata(target)
        return LockedVaultInfo(
            path=target,
            format_version=record.header.version,
            kdf_profile=record.header.kdf_profile,
            container_size=record.header.container_size,
        )

    @classmethod
    def read_unlocked_info(cls, path: str | Path, *, passphrase: str) -> UnlockedVaultInfo:
        """Read authenticated outer-volume metadata with the supplied passphrase."""
        unlocked = cls._unlock_outer_metadata(Path(path), passphrase=passphrase)
        return UnlockedVaultInfo(
            path=unlocked.path,
            active_volume="outer",
            format_version=unlocked.record.header.version,
            kdf_profile=unlocked.record.header.kdf_profile,
            created_at=unlocked.index.created_at,
            file_count=len(unlocked.index.files),
            encrypted_size=cls._existing_outer_encrypted_length(unlocked),
        )

    @classmethod
    def read_hidden_info(
        cls,
        path: str | Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> UnlockedVaultInfo:
        """Read authenticated hidden-volume metadata."""
        unlocked = cls._unlock_hidden_state(
            Path(path),
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )
        return UnlockedVaultInfo(
            path=unlocked.outer.path,
            active_volume="hidden",
            format_version=unlocked.outer.record.header.version,
            kdf_profile=unlocked.outer.record.header.kdf_profile,
            created_at=unlocked.hidden.index.created_at,
            file_count=len(unlocked.hidden.index.files),
            encrypted_size=cls._existing_hidden_encrypted_length(unlocked),
        )

    @classmethod
    def list_files(cls, path: str | Path, *, passphrase: str) -> list[ListedVaultFile]:
        """List authenticated file metadata for the outer volume."""
        unlocked = cls._unlock_outer_metadata(Path(path), passphrase=passphrase)
        return cls._list_index_files(unlocked.index)

    @classmethod
    def list_hidden_files(
        cls,
        path: str | Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> list[ListedVaultFile]:
        """List authenticated file metadata for the hidden volume."""
        unlocked = cls._unlock_hidden_state(
            Path(path),
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )
        return cls._list_index_files(unlocked.hidden.index)

    @classmethod
    def _unlock(cls, path: Path, *, passphrase: str) -> UnlockedVault:
        return cls._materialize_outer(cls._unlock_outer_metadata(path, passphrase=passphrase))

    @classmethod
    def _unlock_metadata(cls, path: Path, *, passphrase: str) -> UnlockedVaultMetadata:
        """Compatibility wrapper around the metadata-first outer unlock path."""
        return cls._unlock_outer_metadata(path, passphrase=passphrase)

    @classmethod
    def _unlock_outer_metadata(cls, path: Path, *, passphrase: str) -> UnlockedVaultMetadata:
        record = ContainerReader.read_path_metadata(path)
        dek = cls._unwrap_dek(record, passphrase=passphrase)
        index = cls._decrypt_index(record, dek=dek)
        return UnlockedVaultMetadata(path=path, record=record, dek=dek, index=index)

    @classmethod
    def _unlock_hidden(
        cls,
        path: Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> UnlockedHiddenVault:
        return cls._materialize_hidden(
            cls._unlock_hidden_state(
                path,
                outer_passphrase=outer_passphrase,
                inner_passphrase=inner_passphrase,
            )
        )

    @classmethod
    def _unlock_hidden_metadata(
        cls,
        path: Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> UnlockedHiddenVaultMetadata:
        """Compatibility wrapper around the metadata-first hidden unlock path."""
        return cls._unlock_hidden_state(
            path,
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )

    @classmethod
    def _unlock_hidden_state(
        cls,
        path: Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> UnlockedHiddenVaultMetadata:
        outer = cls._unlock_outer_metadata(path, passphrase=outer_passphrase)
        if outer.index.reserved_tail_start is None:
            raise HiddenVolumeError("No hidden volume is configured for this vault.")

        hidden_offset = outer.index.reserved_tail_start
        hidden_size = outer.record.encrypted_data_size - cls._existing_outer_encrypted_length(outer)
        hidden = unlock_hidden_region_metadata(
            path,
            offset=hidden_offset,
            size=hidden_size,
            passphrase=inner_passphrase,
            kdf_profile=outer.record.header.kdf_profile,
        )
        return UnlockedHiddenVaultMetadata(outer=outer, hidden=hidden)

    @classmethod
    def _materialize_outer(cls, unlocked: UnlockedVaultMetadata) -> UnlockedVault:
        outer_encrypted_data = cls._outer_ciphertext_source(unlocked).read(
            0,
            cls._existing_outer_encrypted_length(unlocked),
        )
        hidden_region = b"".join(
            cls._read_segment_bytes(segment)
            for segment in cls._existing_hidden_file_segments(unlocked)
        )
        return UnlockedVault(
            path=unlocked.path,
            record=unlocked.record,
            dek=unlocked.dek,
            index=unlocked.index,
            outer_encrypted_data=outer_encrypted_data,
            hidden_region=hidden_region,
        )

    @classmethod
    def _materialize_hidden(cls, unlocked: UnlockedHiddenVaultMetadata) -> UnlockedHiddenVault:
        return UnlockedHiddenVault(
            outer=cls._materialize_outer(unlocked.outer),
            hidden=MaterializedHiddenRegion(
                record=unlocked.hidden.record,
                dek=unlocked.hidden.dek,
                index=unlocked.hidden.index,
                encrypted_data=cls._hidden_ciphertext_source(unlocked).read(
                    0,
                    cls._existing_hidden_encrypted_length(unlocked),
                ),
            ),
        )

    @classmethod
    def _unwrap_dek(
        cls,
        record: ContainerMetadataRecord,
        *,
        passphrase: str,
    ) -> bytes:
        kek = KdfService.derive_key(passphrase, record.outer_salt, record.header.kdf_profile)
        header_bytes = pack_public_header(record.header)
        return EncryptionService.unwrap_dek(kek, record.wrapped_dek, header_bytes)

    @classmethod
    def _decrypt_index(
        cls,
        record: ContainerMetadataRecord,
        *,
        dek: bytes,
    ) -> VolumeIndex:
        if len(record.encrypted_index) <= 12:
            raise ContainerFormatError("Encrypted index payload is too small to contain a nonce.")

        nonce = record.encrypted_index[:12]
        ciphertext = record.encrypted_index[12:]

        try:
            plaintext = EncryptionService.decrypt_chunk(
                dek,
                EncryptedPayload(nonce=nonce, ciphertext=ciphertext),
                INDEX_AAD,
            )
        except CryptoAuthenticationError as exc:
            raise CryptoAuthenticationError(
                "Vault unlock failed: wrong passphrase or corrupted index."
            ) from exc

        return deserialize_index(plaintext)

    @staticmethod
    def _encrypt_index(index: VolumeIndex, dek: bytes) -> bytes:
        if len(dek) != AES256_KEY_BYTES:
            raise ContainerFormatError("DEK must be 32 bytes when encrypting the index.")

        plaintext = serialize_index(index)
        payload = EncryptionService.encrypt_chunk(dek, plaintext, INDEX_AAD)
        return payload.nonce + payload.ciphertext

    @classmethod
    def _write_updated_vault_from_segments(
        cls,
        unlocked: UnlockedVaultMetadata,
        *,
        passphrase: str,
        index: VolumeIndex,
        encrypted_data_segments: Sequence[bytes | EncryptedDataFileSegment],
        outer_encrypted_length: int,
    ) -> Path:
        resolved_index = cls._resolve_hidden_boundary(index, outer_encrypted_length)
        encrypted_index = cls._encrypt_index(resolved_index, unlocked.dek)
        encrypted_data_length = cls._encrypted_data_segment_length(encrypted_data_segments)
        container_size = 32 + 32 + 12 + 48 + 4 + len(encrypted_index) + encrypted_data_length
        new_header = PublicHeader(
            version=unlocked.record.header.version,
            flags=unlocked.record.header.flags,
            kdf_profile=unlocked.record.header.kdf_profile,
            container_size=container_size,
        )
        kek = KdfService.derive_key(passphrase, unlocked.record.outer_salt, new_header.kdf_profile)
        wrapped_dek = EncryptionService.wrap_dek(
            kek,
            unlocked.dek,
            pack_public_header(new_header),
        )

        request = ContainerWriteRequest(
            header=new_header,
            outer_salt=unlocked.record.outer_salt,
            wrapped_dek=wrapped_dek,
            encrypted_index=encrypted_index,
            encrypted_data_segments=tuple(encrypted_data_segments),
        )
        return ContainerWriter.write_atomic(unlocked.path, request)

    @classmethod
    def _write_updated_hidden_volume_from_segments(
        cls,
        unlocked: UnlockedHiddenVaultMetadata,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
        index: VolumeIndex,
        hidden_encrypted_data_segments: Sequence[bytes | EncryptedDataFileSegment],
        hidden_encrypted_length: int,
    ) -> Path:
        prefix = serialize_hidden_region_prefix(
            passphrase=inner_passphrase,
            kdf_profile=unlocked.outer.record.header.kdf_profile,
            dek=unlocked.hidden.dek,
            index=index,
            salt=unlocked.hidden.record.salt,
        )
        padding_length = unlocked.hidden.record.total_size - len(prefix) - hidden_encrypted_length
        if padding_length < 0:
            raise HiddenVolumeError("Hidden volume is full; not enough reserved space remains.")

        hidden_region_segments: tuple[bytes | EncryptedDataFileSegment, ...] = (
            prefix,
            *hidden_encrypted_data_segments,
            secrets.token_bytes(padding_length),
        )
        return cls._write_updated_vault_from_segments(
            unlocked.outer,
            passphrase=outer_passphrase,
            index=unlocked.outer.index,
            encrypted_data_segments=(
                *cls._existing_encrypted_file_segments(unlocked.outer, include_hidden=False),
                *hidden_region_segments,
            ),
            outer_encrypted_length=cls._existing_outer_encrypted_length(unlocked.outer),
        )

    @classmethod
    def _existing_encrypted_file_segments(
        cls,
        unlocked: UnlockedVaultMetadata,
        *,
        include_hidden: bool = True,
    ) -> tuple[EncryptedDataFileSegment, ...]:
        encrypted_data_offset = unlocked.record.encrypted_data_offset
        encrypted_data_size = unlocked.record.encrypted_data_size

        if unlocked.index.reserved_tail_start is None:
            if not include_hidden or encrypted_data_size == 0:
                return () if encrypted_data_size == 0 else (
                    EncryptedDataFileSegment(
                        path=unlocked.path,
                        offset=encrypted_data_offset,
                        length=encrypted_data_size,
                    ),
                )
            return (
                EncryptedDataFileSegment(
                    path=unlocked.path,
                    offset=encrypted_data_offset,
                    length=encrypted_data_size,
                ),
            )

        outer_length = unlocked.index.reserved_tail_start - encrypted_data_offset
        hidden_length = encrypted_data_size - outer_length
        segments: list[EncryptedDataFileSegment] = []
        if outer_length > 0:
            segments.append(
                EncryptedDataFileSegment(
                    path=unlocked.path,
                    offset=encrypted_data_offset,
                    length=outer_length,
                )
            )
        if include_hidden and hidden_length > 0:
            segments.append(
                EncryptedDataFileSegment(
                    path=unlocked.path,
                    offset=unlocked.index.reserved_tail_start,
                    length=hidden_length,
                )
            )
        return tuple(segments)

    @classmethod
    def _existing_hidden_file_segments(
        cls,
        unlocked: UnlockedVaultMetadata,
    ) -> tuple[EncryptedDataFileSegment, ...]:
        if unlocked.index.reserved_tail_start is None:
            return ()

        outer_length = cls._existing_outer_encrypted_length(unlocked)
        hidden_length = unlocked.record.encrypted_data_size - outer_length
        if hidden_length <= 0:
            return ()
        return (
            EncryptedDataFileSegment(
                path=unlocked.path,
                offset=unlocked.index.reserved_tail_start,
                length=hidden_length,
            ),
        )

    @classmethod
    def _existing_hidden_encrypted_file_segments(
        cls,
        unlocked: UnlockedHiddenVaultMetadata,
    ) -> tuple[EncryptedDataFileSegment, ...]:
        hidden_length = cls._existing_hidden_encrypted_length(unlocked)
        hidden_region_start = unlocked.outer.index.reserved_tail_start
        if hidden_length == 0:
            return ()
        if hidden_region_start is None:
            raise HiddenVolumeError("No hidden volume is configured for this vault.")

        return (
            EncryptedDataFileSegment(
                path=unlocked.outer.path,
                offset=hidden_region_start + unlocked.hidden.record.encrypted_data_offset,
                length=hidden_length,
            ),
        )

    @staticmethod
    def _existing_outer_encrypted_length(unlocked: UnlockedVaultMetadata) -> int:
        if unlocked.index.reserved_tail_start is None:
            return unlocked.record.encrypted_data_size
        return unlocked.index.reserved_tail_start - unlocked.record.encrypted_data_offset

    @staticmethod
    def _existing_hidden_encrypted_length(unlocked: UnlockedHiddenVaultMetadata) -> int:
        used = 0
        for file_record in unlocked.hidden.index.files:
            for chunk in file_record.chunks:
                used = max(used, chunk.offset + chunk.ciphertext_size)
        return used

    @staticmethod
    def _encrypted_data_segment_length(
        segments: Sequence[bytes | EncryptedDataFileSegment],
    ) -> int:
        return sum(
            len(segment) if isinstance(segment, bytes) else segment.length
            for segment in segments
        )

    @staticmethod
    def _outer_ciphertext_source(
        unlocked: UnlockedVaultMetadata | UnlockedVault,
    ) -> CiphertextSource:
        if isinstance(unlocked, UnlockedVault):
            return InMemoryCiphertextSource(unlocked.outer_encrypted_data)
        return FileCiphertextSource(
            path=unlocked.path,
            base_offset=unlocked.record.encrypted_data_offset,
        )

    @classmethod
    def _hidden_ciphertext_source(
        cls,
        unlocked: UnlockedHiddenVaultMetadata | UnlockedHiddenVault,
    ) -> CiphertextSource:
        if isinstance(unlocked, UnlockedHiddenVault):
            return InMemoryCiphertextSource(unlocked.hidden.encrypted_data)

        hidden_region_start = unlocked.outer.index.reserved_tail_start
        if hidden_region_start is None:
            raise HiddenVolumeError("No hidden volume is configured for this vault.")

        return FileCiphertextSource(
            path=unlocked.outer.path,
            base_offset=hidden_region_start + unlocked.hidden.record.encrypted_data_offset,
        )

    @staticmethod
    def _list_index_files(index: VolumeIndex) -> list[ListedVaultFile]:
        return [
            ListedVaultFile(
                path=file.path,
                original_size=file.original_size,
                added_at=file.added_at,
            )
            for file in index.files
        ]

    @staticmethod
    def _get_file_record(index: VolumeIndex, internal_path: str) -> FileRecord:
        for file_record in index.files:
            if file_record.path == internal_path:
                return file_record
        raise VaultFileNotFoundError(
            f"Internal path not found in vault: {internal_path}. "
            "Run `vault list` first to inspect the stored paths."
        )

    @staticmethod
    def _read_segment_bytes(segment: EncryptedDataFileSegment) -> bytes:
        with segment.path.open("rb") as handle:
            handle.seek(segment.offset)
            data = handle.read(segment.length)
        if len(data) != segment.length:
            raise ContainerFormatError("Encrypted data segment is truncated on disk.")
        return data

    @classmethod
    def _resolve_hidden_boundary(
        cls,
        index: VolumeIndex,
        outer_encrypted_data_len: int,
    ) -> VolumeIndex:
        if index.reserved_tail_start is None:
            return index

        base_bytes = 32 + 32 + 12 + 48 + 4
        candidate = index.reserved_tail_start
        for _ in range(4):
            test_index = VolumeIndex(
                version=index.version,
                created_at=index.created_at,
                reserved_tail_start=candidate,
                files=index.files,
            )
            predicted_index_len = 12 + len(serialize_index(test_index)) + 16
            updated_candidate = base_bytes + predicted_index_len + outer_encrypted_data_len
            if updated_candidate == candidate:
                return test_index
            candidate = updated_candidate

        return VolumeIndex(
            version=index.version,
            created_at=index.created_at,
            reserved_tail_start=candidate,
            files=index.files,
        )


def _iter_source_files(source: Path) -> list[tuple[str, Path]]:
    if source.is_file():
        return [(source.name, source)]

    if source.is_dir():
        return [
            (str(path.relative_to(source.parent)).replace("\\", "/"), path)
            for path in sorted(source.rglob("*"))
            if path.is_file()
        ]

    raise ContainerFormatError(f"Source path does not exist or is unsupported: {source}")
