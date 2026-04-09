"""High-level outer-volume operations for the current VaultCLI slice."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import secrets
import time
from typing import Final, Sequence

from vaultcli.container.format import PublicHeader, pack_public_header
from vaultcli.container.index import ChunkRecord, FileRecord, VolumeIndex, deserialize_index, serialize_index
from vaultcli.container.reader import ContainerReader, ContainerRecord
from vaultcli.container.writer import ContainerWriteRequest, ContainerWriter
from vaultcli.crypto.aes_gcm import AES256_KEY_BYTES, EncryptedPayload, EncryptionService
from vaultcli.crypto.kdf import KdfProfileName, KdfService
from vaultcli.errors import (
    ContainerFormatError,
    CryptoAuthenticationError,
    HiddenVolumeError,
    VaultFileNotFoundError,
)
from vaultcli.passphrases import enforce_passphrase_policy
from vaultcli.vault.hidden import (
    UnlockedHiddenRegion,
    build_hidden_region,
    serialize_hidden_region,
    unlock_hidden_region,
)


INDEX_AAD: Final[bytes] = b"vaultcli:outer-index"
DEFAULT_CHUNK_SIZE: Final[int] = 1024 * 1024


@dataclass(frozen=True, slots=True)
class LockedVaultInfo:
    """Metadata visible without decrypting the encrypted index."""

    path: Path
    format_version: int
    kdf_profile: KdfProfileName
    container_size: int


@dataclass(frozen=True, slots=True)
class UnlockedVaultInfo:
    """Authenticated metadata for the active outer volume."""

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
    """Unlocked outer-volume material needed for authenticated operations."""

    path: Path
    record: ContainerRecord
    dek: bytes
    index: VolumeIndex
    outer_encrypted_data: bytes
    hidden_region: bytes


@dataclass(frozen=True, slots=True)
class UnlockedHiddenVault:
    """Unlocked hidden-volume material plus the outer container context."""

    outer: UnlockedVault
    hidden: UnlockedHiddenRegion


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
        unlocked = cls._unlock(Path(vault_path), passphrase=current_passphrase)
        return cls._write_updated_vault(
            unlocked,
            passphrase=new_passphrase,
            index=unlocked.index,
            outer_encrypted_data=unlocked.outer_encrypted_data,
            hidden_region=unlocked.hidden_region,
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
        unlocked = cls._unlock(Path(vault_path), passphrase=outer_passphrase)
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
        return cls._write_updated_vault(
            unlocked,
            passphrase=outer_passphrase,
            index=new_index,
            outer_encrypted_data=unlocked.outer_encrypted_data,
            hidden_region=hidden_region,
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
        unlocked = cls._unlock(Path(vault_path), passphrase=passphrase)
        encrypted_data = bytearray(unlocked.outer_encrypted_data)
        files_by_path = {file.path: file for file in unlocked.index.files}
        added_files: list[AddedVaultFile] = []
        now = int(time.time())

        for source in sources:
            for internal_path, source_path in _iter_source_files(Path(source)):
                plaintext = source_path.read_bytes()
                file_record = cls._encrypt_file(
                    internal_path=internal_path,
                    plaintext=plaintext,
                    dek=unlocked.dek,
                    encrypted_data=encrypted_data,
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
        cls._write_updated_vault(
            unlocked,
            passphrase=passphrase,
            index=new_index,
            outer_encrypted_data=bytes(encrypted_data),
            hidden_region=unlocked.hidden_region,
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
        unlocked = cls._unlock_hidden(Path(vault_path), outer_passphrase=outer_passphrase, inner_passphrase=inner_passphrase)
        encrypted_data = bytearray(unlocked.hidden.encrypted_data)
        files_by_path = {file.path: file for file in unlocked.hidden.index.files}
        added_files: list[AddedVaultFile] = []
        now = int(time.time())

        for source in sources:
            for internal_path, source_path in _iter_source_files(Path(source)):
                plaintext = source_path.read_bytes()
                file_record = cls._encrypt_file(
                    internal_path=internal_path,
                    plaintext=plaintext,
                    dek=unlocked.hidden.dek,
                    encrypted_data=encrypted_data,
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
        cls._write_updated_hidden_volume(
            unlocked,
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
            index=new_index,
            hidden_encrypted_data=bytes(encrypted_data),
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
            raise ContainerFormatError("Specify an internal path or use --all.")

        unlocked = cls._unlock(Path(vault_path), passphrase=passphrase)
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        if extract_all:
            selected = list(unlocked.index.files)
        else:
            selected = [cls._get_file_record(unlocked.index, internal_path or "")]

        extracted: list[ExtractedVaultFile] = []
        for file_record in selected:
            plaintext = cls._decrypt_file(file_record, unlocked.outer_encrypted_data, unlocked.dek)
            destination = target_dir / Path(file_record.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and not overwrite:
                raise ContainerFormatError(
                    f"Refusing to overwrite existing file without --overwrite: {destination}"
                )
            destination.write_bytes(plaintext)
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
            raise ContainerFormatError("Specify an internal path or use --all.")

        unlocked = cls._unlock_hidden(
            Path(vault_path),
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        if extract_all:
            selected = list(unlocked.hidden.index.files)
        else:
            selected = [cls._get_file_record(unlocked.hidden.index, internal_path or "")]

        extracted: list[ExtractedVaultFile] = []
        for file_record in selected:
            plaintext = cls._decrypt_file(file_record, unlocked.hidden.encrypted_data, unlocked.hidden.dek)
            destination = target_dir / Path(file_record.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and not overwrite:
                raise ContainerFormatError(
                    f"Refusing to overwrite existing file without --overwrite: {destination}"
                )
            destination.write_bytes(plaintext)
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
        unlocked = cls._unlock(Path(path), passphrase=passphrase)
        checked_chunks = 0

        for file_record in unlocked.index.files:
            cls._decrypt_file(file_record, unlocked.outer_encrypted_data, unlocked.dek)
            checked_chunks += len(file_record.chunks)

        return VerificationResult(
            mode="unlocked",
            active_volume="outer",
            status="verified",
            checked_files=len(unlocked.index.files),
            checked_chunks=checked_chunks,
        )

    @classmethod
    def read_locked_info(cls, path: str | Path) -> LockedVaultInfo:
        """Read public header metadata without decrypting the encrypted index."""
        target = Path(path)
        record = ContainerReader.read_path(target)
        return LockedVaultInfo(
            path=target,
            format_version=record.header.version,
            kdf_profile=record.header.kdf_profile,
            container_size=record.header.container_size,
        )

    @classmethod
    def read_unlocked_info(cls, path: str | Path, *, passphrase: str) -> UnlockedVaultInfo:
        """Read authenticated outer-volume metadata with the supplied passphrase."""
        unlocked = cls._unlock(Path(path), passphrase=passphrase)
        return UnlockedVaultInfo(
            path=unlocked.path,
            active_volume="outer",
            format_version=unlocked.record.header.version,
            kdf_profile=unlocked.record.header.kdf_profile,
            created_at=unlocked.index.created_at,
            file_count=len(unlocked.index.files),
            encrypted_size=len(unlocked.outer_encrypted_data),
        )

    @classmethod
    def list_files(cls, path: str | Path, *, passphrase: str) -> list[ListedVaultFile]:
        """List authenticated file metadata for the outer volume."""
        unlocked = cls._unlock(Path(path), passphrase=passphrase)
        return [
            ListedVaultFile(
                path=file.path,
                original_size=file.original_size,
                added_at=file.added_at,
            )
            for file in unlocked.index.files
        ]

    @classmethod
    def list_hidden_files(
        cls,
        path: str | Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> list[ListedVaultFile]:
        """List authenticated file metadata for the hidden volume."""
        unlocked = cls._unlock_hidden(
            Path(path),
            outer_passphrase=outer_passphrase,
            inner_passphrase=inner_passphrase,
        )
        return [
            ListedVaultFile(
                path=file.path,
                original_size=file.original_size,
                added_at=file.added_at,
            )
            for file in unlocked.hidden.index.files
        ]

    @classmethod
    def _unlock(cls, path: Path, *, passphrase: str) -> UnlockedVault:
        record = ContainerReader.read_path(path)
        dek = cls._unwrap_dek(record, passphrase=passphrase)
        index = cls._decrypt_index(record, dek=dek)
        outer_encrypted_data, hidden_region = cls._split_outer_and_hidden(record, index)
        return UnlockedVault(
            path=path,
            record=record,
            dek=dek,
            index=index,
            outer_encrypted_data=outer_encrypted_data,
            hidden_region=hidden_region,
        )

    @classmethod
    def _unlock_hidden(
        cls,
        path: Path,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
    ) -> UnlockedHiddenVault:
        outer = cls._unlock(path, passphrase=outer_passphrase)
        if not outer.hidden_region:
            raise HiddenVolumeError("No hidden volume is configured for this vault.")

        hidden = unlock_hidden_region(
            outer.hidden_region,
            passphrase=inner_passphrase,
            kdf_profile=outer.record.header.kdf_profile,
        )
        return UnlockedHiddenVault(outer=outer, hidden=hidden)

    @classmethod
    def _unwrap_dek(cls, record: ContainerRecord, *, passphrase: str) -> bytes:
        kek = KdfService.derive_key(passphrase, record.outer_salt, record.header.kdf_profile)
        header_bytes = pack_public_header(record.header)
        return EncryptionService.unwrap_dek(kek, record.wrapped_dek, header_bytes)

    @classmethod
    def _decrypt_index(cls, record: ContainerRecord, *, dek: bytes) -> VolumeIndex:
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
            raise CryptoAuthenticationError("Vault unlock failed: wrong passphrase or corrupted index.") from exc

        return deserialize_index(plaintext)

    @staticmethod
    def _encrypt_index(index: VolumeIndex, dek: bytes) -> bytes:
        if len(dek) != AES256_KEY_BYTES:
            raise ContainerFormatError("DEK must be 32 bytes when encrypting the index.")

        plaintext = serialize_index(index)
        payload = EncryptionService.encrypt_chunk(dek, plaintext, INDEX_AAD)
        return payload.nonce + payload.ciphertext

    @classmethod
    def _write_updated_vault(
        cls,
        unlocked: UnlockedVault,
        *,
        passphrase: str,
        index: VolumeIndex,
        outer_encrypted_data: bytes,
        hidden_region: bytes,
    ) -> Path:
        resolved_index = cls._resolve_hidden_boundary(index, len(outer_encrypted_data))
        encrypted_index = cls._encrypt_index(resolved_index, unlocked.dek)
        combined_data = outer_encrypted_data + hidden_region
        container_size = 32 + 32 + 12 + 48 + 4 + len(encrypted_index) + len(combined_data)
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
            encrypted_data=combined_data,
        )
        return ContainerWriter.write_atomic(unlocked.path, request)

    @classmethod
    def _write_updated_hidden_volume(
        cls,
        unlocked: UnlockedHiddenVault,
        *,
        outer_passphrase: str,
        inner_passphrase: str,
        index: VolumeIndex,
        hidden_encrypted_data: bytes,
    ) -> Path:
        hidden_region = serialize_hidden_region(
            passphrase=inner_passphrase,
            kdf_profile=unlocked.outer.record.header.kdf_profile,
            dek=unlocked.hidden.dek,
            index=index,
            encrypted_data=hidden_encrypted_data,
            total_size=unlocked.hidden.record.total_size,
            salt=unlocked.hidden.record.salt,
        )
        return cls._write_updated_vault(
            unlocked.outer,
            passphrase=outer_passphrase,
            index=unlocked.outer.index,
            outer_encrypted_data=unlocked.outer.outer_encrypted_data,
            hidden_region=hidden_region,
        )

    @classmethod
    def _encrypt_file(
        cls,
        *,
        internal_path: str,
        plaintext: bytes,
        dek: bytes,
        encrypted_data: bytearray,
        added_at: int,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> FileRecord:
        chunks: list[ChunkRecord] = []
        encrypted_size = 0
        total_chunks = max(1, (len(plaintext) + chunk_size - 1) // chunk_size)

        for chunk_index in range(total_chunks):
            start = chunk_index * chunk_size
            end = start + chunk_size
            plaintext_chunk = plaintext[start:end]
            if len(plaintext) == 0:
                plaintext_chunk = b""

            payload = EncryptionService.encrypt_chunk(
                dek,
                plaintext_chunk,
                _chunk_aad(internal_path, chunk_index, chunk_index == total_chunks - 1),
            )
            offset = len(encrypted_data)
            encrypted_data.extend(payload.ciphertext)
            chunks.append(
                ChunkRecord(
                    nonce=payload.nonce,
                    offset=offset,
                    ciphertext_size=len(payload.ciphertext),
                )
            )
            encrypted_size += len(payload.ciphertext)

            if len(plaintext) == 0:
                break

        return FileRecord(
            path=internal_path,
            original_size=len(plaintext),
            encrypted_size=encrypted_size,
            chunk_size=chunk_size,
            chunks=tuple(chunks),
            added_at=added_at,
            sha256=sha256(plaintext).hexdigest(),
        )

    @classmethod
    def _decrypt_file(cls, file_record: FileRecord, encrypted_data: bytes, dek: bytes) -> bytes:
        plaintext_parts: list[bytes] = []
        for chunk_index, chunk in enumerate(file_record.chunks):
            start = chunk.offset
            end = start + chunk.ciphertext_size
            ciphertext = encrypted_data[start:end]
            if len(ciphertext) != chunk.ciphertext_size:
                raise ContainerFormatError(
                    f"Encrypted chunk for {file_record.path} is truncated at chunk {chunk_index}."
                )

            plaintext_parts.append(
                EncryptionService.decrypt_chunk(
                    dek,
                    EncryptedPayload(nonce=chunk.nonce, ciphertext=ciphertext),
                    _chunk_aad(
                        file_record.path,
                        chunk_index,
                        chunk_index == len(file_record.chunks) - 1,
                    ),
                )
            )

        plaintext = b"".join(plaintext_parts)
        if sha256(plaintext).hexdigest() != file_record.sha256:
            raise ContainerFormatError(f"SHA-256 mismatch while extracting {file_record.path}.")
        return plaintext

    @staticmethod
    def _get_file_record(index: VolumeIndex, internal_path: str) -> FileRecord:
        for file_record in index.files:
            if file_record.path == internal_path:
                return file_record
        raise VaultFileNotFoundError(f"Internal path not found in vault: {internal_path}")

    @staticmethod
    def _split_outer_and_hidden(record: ContainerRecord, index: VolumeIndex) -> tuple[bytes, bytes]:
        if index.reserved_tail_start is None:
            return record.encrypted_data, b""

        reserved_tail_offset = index.reserved_tail_start - record.encrypted_data_offset
        if reserved_tail_offset < 0 or reserved_tail_offset > len(record.encrypted_data):
            raise HiddenVolumeError("Reserved tail start is outside the encrypted data region.")

        return (
            record.encrypted_data[:reserved_tail_offset],
            record.encrypted_data[reserved_tail_offset:],
        )

    @classmethod
    def _resolve_hidden_boundary(cls, index: VolumeIndex, outer_encrypted_data_len: int) -> VolumeIndex:
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


def _chunk_aad(internal_path: str, chunk_index: int, is_final: bool) -> bytes:
    return f"{internal_path}|chunk={chunk_index}|final={int(is_final)}".encode("utf-8")
