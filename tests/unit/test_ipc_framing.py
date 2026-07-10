from __future__ import annotations

import asyncio
import struct

import pytest

from diagnose.ipc import (
    CONTROL_FRAME_LIMIT,
    RESULT_FRAME_LIMIT,
    ProtocolError,
    ProtocolErrorCode,
    pack_frame,
    read_frame,
)


def make_reader(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def test_pack_frame_uses_four_byte_unsigned_big_endian_length() -> None:
    framed = pack_frame(b"hello")

    assert framed[:4] == b"\x00\x00\x00\x05"
    assert struct.unpack(">I", framed[:4])[0] == 5
    assert framed[4:] == b"hello"


@pytest.mark.asyncio
async def test_read_frame_returns_exact_payload() -> None:
    assert await read_frame(make_reader(pack_frame(b'{"ok":true}'))) == b'{"ok":true}'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("wire", "code"),
    [
        (b"", ProtocolErrorCode.CONNECTION_CLOSED),
        (b"\x00\x00", ProtocolErrorCode.MALFORMED_FRAME),
        (b"\x00\x00\x00\x00", ProtocolErrorCode.MALFORMED_FRAME),
        (b"\x00\x00\x00\x05ab", ProtocolErrorCode.MALFORMED_FRAME),
    ],
)
async def test_read_frame_rejects_closed_empty_and_truncated_frames(
    wire: bytes,
    code: ProtocolErrorCode,
) -> None:
    with pytest.raises(ProtocolError) as caught:
        await read_frame(make_reader(wire))

    assert caught.value.code is code


@pytest.mark.asyncio
async def test_read_frame_rejects_oversize_from_header_without_reading_body() -> None:
    header_only = struct.pack(">I", CONTROL_FRAME_LIMIT + 1)

    with pytest.raises(ProtocolError) as caught:
        await read_frame(make_reader(header_only))

    assert caught.value.code is ProtocolErrorCode.FRAME_TOO_LARGE


def test_control_and_result_limits_are_enforced() -> None:
    payload = b"x" * (CONTROL_FRAME_LIMIT + 1)

    with pytest.raises(ProtocolError) as caught:
        pack_frame(payload, max_size=CONTROL_FRAME_LIMIT)

    assert caught.value.code is ProtocolErrorCode.FRAME_TOO_LARGE
    assert pack_frame(payload, max_size=RESULT_FRAME_LIMIT)[4:] == payload


@pytest.mark.parametrize("limit", [0, -1, RESULT_FRAME_LIMIT + 1])
def test_frame_limit_must_stay_within_global_limit(limit: int) -> None:
    with pytest.raises(ValueError):
        pack_frame(b"x", max_size=limit)
