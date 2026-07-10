"""Length-prefixed asyncio framing for the local IPC protocol."""

from __future__ import annotations

import asyncio
import struct

from diagnose.ipc.errors import ProtocolError, ProtocolErrorCode
from diagnose.ipc.protocol import Envelope

CONTROL_FRAME_LIMIT = 1 * 1024 * 1024
RESULT_FRAME_LIMIT = 8 * 1024 * 1024
GLOBAL_FRAME_LIMIT = RESULT_FRAME_LIMIT
_HEADER_SIZE = 4


def pack_frame(payload: bytes, *, max_size: int = CONTROL_FRAME_LIMIT) -> bytes:
    """Prefix payload with its four-byte unsigned big-endian length."""

    _validate_limit(max_size)
    size = len(payload)
    if size == 0:
        raise ProtocolError(ProtocolErrorCode.MALFORMED_FRAME, "Frames cannot be empty.")
    if size > max_size:
        raise ProtocolError(
            ProtocolErrorCode.FRAME_TOO_LARGE,
            f"Frame exceeds the {max_size}-byte limit.",
        )
    return struct.pack(">I", size) + payload


async def read_frame(
    reader: asyncio.StreamReader,
    *,
    max_size: int = CONTROL_FRAME_LIMIT,
) -> bytes:
    """Read one complete frame and reject truncation and oversized lengths."""

    _validate_limit(max_size)
    try:
        header = await reader.readexactly(_HEADER_SIZE)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            raise ProtocolError(
                ProtocolErrorCode.CONNECTION_CLOSED,
                "Connection closed before a frame was received.",
            ) from exc
        raise ProtocolError(
            ProtocolErrorCode.MALFORMED_FRAME,
            "Connection closed during the frame header.",
        ) from exc

    size = struct.unpack(">I", header)[0]
    if size == 0:
        raise ProtocolError(ProtocolErrorCode.MALFORMED_FRAME, "Frames cannot be empty.")
    if size > max_size:
        raise ProtocolError(
            ProtocolErrorCode.FRAME_TOO_LARGE,
            f"Frame exceeds the {max_size}-byte limit.",
        )

    try:
        return await reader.readexactly(size)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError(
            ProtocolErrorCode.MALFORMED_FRAME,
            "Connection closed during the frame payload.",
        ) from exc


async def write_frame(
    writer: asyncio.StreamWriter,
    payload: bytes,
    *,
    max_size: int = CONTROL_FRAME_LIMIT,
) -> None:
    """Write and drain one complete length-prefixed frame."""

    writer.write(pack_frame(payload, max_size=max_size))
    try:
        await writer.drain()
    except (ConnectionError, BrokenPipeError) as exc:
        raise ProtocolError(
            ProtocolErrorCode.CONNECTION_CLOSED,
            "Connection closed while sending a frame.",
        ) from exc


async def read_envelope(
    reader: asyncio.StreamReader,
    *,
    max_size: int = CONTROL_FRAME_LIMIT,
) -> Envelope:
    return Envelope.from_wire_bytes(await read_frame(reader, max_size=max_size))


async def write_envelope(
    writer: asyncio.StreamWriter,
    envelope: Envelope,
    *,
    max_size: int = CONTROL_FRAME_LIMIT,
) -> None:
    await write_frame(writer, envelope.to_wire_bytes(), max_size=max_size)


def _validate_limit(max_size: int) -> None:
    if not 0 < max_size <= GLOBAL_FRAME_LIMIT:
        raise ValueError(f"max_size must be between 1 and {GLOBAL_FRAME_LIMIT}")


__all__ = [
    "CONTROL_FRAME_LIMIT",
    "GLOBAL_FRAME_LIMIT",
    "RESULT_FRAME_LIMIT",
    "pack_frame",
    "read_envelope",
    "read_frame",
    "write_envelope",
    "write_frame",
]
