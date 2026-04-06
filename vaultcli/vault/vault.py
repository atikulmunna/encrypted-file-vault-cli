"""High-level outer-volume operations for the current VaultCLI slice."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import secrets
from typing import Final

from vaultcli.container.format import PublicHeader, pack_public_header
from vaultcli.container.index import VolumeIndex, deserialize_index, serialize_index
from vaultcli.container.reader import ContainerReader, ContainerRecord
from vaultcli.container.writer import ContainerWriteRequest, ContainerWriter
from vaultcli.crypto.aes_gcm import AES256_KEY_BYTES, EncryptedPayload, EncryptionService
from vaultcli.crypto.kdf import KdfProfileName, KdfService
from vaultcli.errors import ContainerFormatError, CryptoAuthenticationError


INDEX_AAD: Final[bytes] = b"vaultcli:outer-index"


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


class VaultService:
    """Current outer-volume service used by the first real CLI commands."""

    @classmethod
    def create_empty_vault(
        cls,
        path: str | Path,
        *,
        passphrase: str,
        kdf_profile: KdfProfileName = KdfProfileName.INTERACTIVE,
    ) -> Path:
        """Create an empty outer-volume vault and write it atomically."""
        index = VolumeIndex(
            version=1,
            created_at=0,
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
        target = Path(path)
        record = ContainerReader.read_path(target)
        index = cls._decrypt_index(record, passphrase=passphrase)
        return UnlockedVaultInfo(
            path=target,
            active_volume="outer",
            format_version=record.header.version,
            kdf_profile=record.header.kdf_profile,
            created_at=index.created_at,
            file_count=len(index.files),
            encrypted_size=len(record.encrypted_data),
        )

    @classmethod
    def list_files(cls, path: str | Path, *, passphrase: str) -> list[ListedVaultFile]:
        """List authenticated file metadata for the outer volume."""
        record = ContainerReader.read_path(path)
        index = cls._decrypt_index(record, passphrase=passphrase)
        return [
            ListedVaultFile(
                path=file.path,
                original_size=file.original_size,
                added_at=file.added_at,
            )
            for file in index.files
        ]

    @classmethod
    def _decrypt_index(cls, record: ContainerRecord, *, passphrase: str) -> VolumeIndex:
        if len(record.encrypted_index) <= 12:
            raise ContainerFormatError("Encrypted index payload is too small to contain a nonce.")

        kek = KdfService.derive_key(passphrase, record.outer_salt, record.header.kdf_profile)
        header_bytes = pack_public_header(record.header)
        dek = EncryptionService.unwrap_dek(kek, record.wrapped_dek, header_bytes)
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
