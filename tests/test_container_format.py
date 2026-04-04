"""Tests for the public container header helpers."""

import pytest

from vaultcli.container.format import (
    FORMAT_VERSION,
    MAGIC,
    PUBLIC_HEADER_SIZE,
    PublicHeader,
    pack_public_header,
    parse_public_header,
)
from vaultcli.crypto.kdf import KdfProfileName
from vaultcli.errors import ContainerFormatError


def test_public_header_round_trip() -> None:
    header = PublicHeader(
        version=FORMAT_VERSION,
        flags=0x01,
        kdf_profile=KdfProfileName.SENSITIVE,
        container_size=1024,
    )

    packed = pack_public_header(header)
    parsed = parse_public_header(packed)

    assert len(packed) == PUBLIC_HEADER_SIZE
    assert parsed == header


def test_parse_public_header_rejects_bad_magic() -> None:
    payload = bytearray(pack_public_header(PublicHeader()))
    payload[: len(MAGIC)] = b"NOTVALID"

    with pytest.raises(ContainerFormatError):
        parse_public_header(bytes(payload))


def test_parse_public_header_rejects_wrong_size() -> None:
    with pytest.raises(ContainerFormatError):
        parse_public_header(b"short")
