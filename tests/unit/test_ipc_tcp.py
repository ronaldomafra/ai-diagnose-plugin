from __future__ import annotations

import os
from pathlib import Path

import pytest

from diagnose.ipc import (
    EndpointDescriptor,
    Envelope,
    LoopbackTcpTransport,
    ProtocolError,
    ProtocolErrorCode,
    TransportKind,
    endpoint_permissions_are_private,
    read_endpoint_descriptor,
    write_endpoint_descriptor,
)


async def echo_handler(request: Envelope) -> Envelope:
    return Envelope(
        message_type=f"{request.message_type}.response",
        payload={"received": request.payload},
    )


@pytest.mark.asyncio
async def test_tcp_round_trip_uses_loopback_descriptor_and_correlates_response(
    tmp_path: Path,
) -> None:
    descriptor_path = tmp_path / "run" / "endpoint.json"
    server = LoopbackTcpTransport(descriptor_path)
    try:
        descriptor = await server.start(echo_handler)
        request = Envelope(message_type="server.info", payload={"request": "summary"})
        client = LoopbackTcpTransport(descriptor_path)

        response = await client.request(request)

        assert descriptor.transport is TransportKind.TCP
        assert descriptor.host == "127.0.0.1"
        assert descriptor.port is not None and descriptor.port > 0
        assert descriptor.auth_token is not None
        assert response.message_type == "server.info.response"
        assert response.correlation_id == request.message_id
        assert response.payload == {"received": {"request": "summary"}}
        assert read_endpoint_descriptor(descriptor_path) == descriptor
    finally:
        await server.close()

    assert not descriptor_path.exists()


@pytest.mark.asyncio
async def test_tcp_rejects_invalid_token_without_echoing_it(tmp_path: Path) -> None:
    descriptor_path = tmp_path / "endpoint.json"
    server = LoopbackTcpTransport(descriptor_path)
    descriptor = await server.start(echo_handler)
    assert descriptor.auth_token is not None
    invalid_token = "invalid-token-" + "x" * 40
    tampered = descriptor.model_copy(update={"auth_token": invalid_token})
    write_endpoint_descriptor(descriptor_path, tampered)
    try:
        client = LoopbackTcpTransport(descriptor_path)

        with pytest.raises(ProtocolError) as caught:
            await client.request(Envelope(message_type="server.info"))

        assert caught.value.code is ProtocolErrorCode.AUTHENTICATION_FAILED
        assert invalid_token not in str(caught.value)
        assert descriptor.auth_token not in str(caught.value)
    finally:
        await server.close()
        descriptor_path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_tcp_rotates_auth_token_on_every_start(tmp_path: Path) -> None:
    descriptor_path = tmp_path / "endpoint.json"
    server = LoopbackTcpTransport(descriptor_path)

    first = await server.start(echo_handler)
    await server.close()
    second = await server.start(echo_handler)
    await server.close()

    assert first.auth_token != second.auth_token


@pytest.mark.asyncio
async def test_tcp_normalizes_protocol_version_mismatch(tmp_path: Path) -> None:
    descriptor_path = tmp_path / "endpoint.json"
    server = LoopbackTcpTransport(descriptor_path)
    await server.start(echo_handler)
    try:
        client = LoopbackTcpTransport(descriptor_path)

        with pytest.raises(ProtocolError) as caught:
            await client.request(Envelope(protocol_version="2.0", message_type="server.info"))

        assert caught.value.code is ProtocolErrorCode.UNSUPPORTED_PROTOCOL
    finally:
        await server.close()


def test_tcp_constructor_refuses_non_loopback_bind(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"127\.0\.0\.1"):
        LoopbackTcpTransport(tmp_path / "endpoint.json", host="0.0.0.0")


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL assertion")
def test_windows_descriptor_acl_contains_only_current_user(tmp_path: Path) -> None:
    import win32api
    import win32con
    import win32security

    path = tmp_path / "endpoint.json"
    descriptor = EndpointDescriptor(
        transport=TransportKind.TCP,
        host="127.0.0.1",
        port=12345,
        auth_token="x" * 32,
        server_pid=os.getpid(),
    )
    write_endpoint_descriptor(path, descriptor)

    assert endpoint_permissions_are_private(path)

    process_token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_QUERY,
    )
    try:
        current_sid = win32security.GetTokenInformation(
            process_token,
            win32security.TokenUser,
        )[0]
    finally:
        process_token.Close()
    security = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = security.GetSecurityDescriptorDacl()

    assert dacl is not None
    assert dacl.GetAceCount() == 1
    assert dacl.GetAce(0)[2] == current_sid
