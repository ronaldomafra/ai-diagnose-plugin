from __future__ import annotations

import os
import socket
import stat
from pathlib import Path

import pytest

from diagnose.ipc import (
    Envelope,
    ProtocolError,
    ProtocolErrorCode,
    UnixDomainSocketTransport,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not hasattr(socket, "AF_UNIX"),
    reason="Unix domain socket permission test",
)


async def echo_handler(request: Envelope) -> Envelope:
    return Envelope(message_type=f"{request.message_type}.response", payload=request.payload)


@pytest.mark.asyncio
async def test_unix_round_trip_enforces_private_permissions_and_removes_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "private" / "diagnose.sock"
    server = UnixDomainSocketTransport(socket_path)
    try:
        await server.start(echo_handler)
        request = Envelope(message_type="server.ping", payload={"nonce": "opaque"})
        client = UnixDomainSocketTransport(socket_path)

        response = await client.request(request)

        assert response.payload == request.payload
        assert response.correlation_id == request.message_id
        assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600
    finally:
        await server.close()

    assert not socket_path.exists()


@pytest.mark.asyncio
async def test_unix_refuses_to_replace_regular_file(tmp_path: Path) -> None:
    socket_path = tmp_path / "diagnose.sock"
    socket_path.write_text("do not delete", encoding="utf-8")
    server = UnixDomainSocketTransport(socket_path)

    with pytest.raises(ProtocolError) as caught:
        await server.start(echo_handler)

    assert caught.value.code is ProtocolErrorCode.ENDPOINT_IN_USE
    assert socket_path.read_text(encoding="utf-8") == "do not delete"
