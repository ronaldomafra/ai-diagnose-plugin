from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from diagnose.ipc import Envelope, LoopbackTcpTransport


async def echo_handler(request: Envelope) -> Envelope:
    return Envelope(message_type=f"{request.message_type}.response", payload=request.payload)


async def close_stream(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_tcp_closes_client_that_never_sends_handshake_frame(tmp_path: Path) -> None:
    server = LoopbackTcpTransport(tmp_path / "endpoint.json", timeout=0.1)
    descriptor = await server.start(echo_handler)
    assert descriptor.host is not None
    assert descriptor.port is not None

    reader, writer = await asyncio.open_connection(descriptor.host, descriptor.port)
    try:
        assert await asyncio.wait_for(reader.read(1), timeout=0.75) == b""

        client = LoopbackTcpTransport(tmp_path / "endpoint.json", timeout=0.5)
        request = Envelope(message_type="server.ping", payload={"healthy": True})
        response = await client.request(request)
        assert response.payload == request.payload
    finally:
        await close_stream(writer)
        await server.close()


@pytest.mark.asyncio
async def test_tcp_caps_pending_handshakes_and_recovers_for_round_trip(
    tmp_path: Path,
) -> None:
    server = LoopbackTcpTransport(
        tmp_path / "endpoint.json",
        timeout=0.5,
        max_pending_handshakes=2,
    )
    descriptor = await server.start(echo_handler)
    assert descriptor.host is not None
    assert descriptor.port is not None

    stalled: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
    excess_writer: asyncio.StreamWriter | None = None
    try:
        for _ in range(2):
            stalled.append(await asyncio.open_connection(descriptor.host, descriptor.port))
        await asyncio.sleep(0.05)

        excess_reader, excess_writer = await asyncio.open_connection(
            descriptor.host,
            descriptor.port,
        )
        assert await asyncio.wait_for(excess_reader.read(1), timeout=0.25) == b""

        for _reader, writer in stalled:
            await close_stream(writer)
        stalled.clear()
        await asyncio.sleep(0.05)

        client = LoopbackTcpTransport(tmp_path / "endpoint.json", timeout=0.5)
        request = Envelope(message_type="server.ping", payload={"healthy": True})
        response = await client.request(request)
        assert response.payload == request.payload
        assert response.correlation_id == request.message_id
    finally:
        for _reader, writer in stalled:
            await close_stream(writer)
        if excess_writer is not None:
            await close_stream(excess_writer)
        await server.close()


@pytest.mark.parametrize("invalid_limit", [0, -1, True, 1.5])
def test_pending_handshake_limit_must_be_positive_integer(
    tmp_path: Path,
    invalid_limit: object,
) -> None:
    with pytest.raises(ValueError, match="max_pending_handshakes"):
        LoopbackTcpTransport(
            tmp_path / "endpoint.json",
            max_pending_handshakes=invalid_limit,  # type: ignore[arg-type]
        )
