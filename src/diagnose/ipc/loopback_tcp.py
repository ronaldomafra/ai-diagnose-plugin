"""Authenticated loopback TCP implementation of local Diagnose IPC."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
import socket
from pathlib import Path
from typing import cast

from diagnose.ipc.descriptor import (
    read_endpoint_descriptor,
    remove_endpoint_descriptor,
    write_endpoint_descriptor,
)
from diagnose.ipc.errors import ProtocolError, ProtocolErrorCode
from diagnose.ipc.framing import CONTROL_FRAME_LIMIT, RESULT_FRAME_LIMIT
from diagnose.ipc.protocol import EndpointDescriptor, Envelope, TransportKind
from diagnose.ipc.transport import (
    DEFAULT_MAX_PENDING_HANDSHAKES,
    LocalIpcTransport,
    RequestHandler,
)

_ALLOWED_HOSTS = {"127.0.0.1", "::1"}


class LoopbackTcpTransport(LocalIpcTransport):
    """TCP loopback transport authenticated by a per-start random token."""

    def __init__(
        self,
        descriptor_path: str | Path,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        control_frame_limit: int = CONTROL_FRAME_LIMIT,
        result_frame_limit: int = RESULT_FRAME_LIMIT,
        timeout: float = 5.0,
        max_pending_handshakes: int = DEFAULT_MAX_PENDING_HANDSHAKES,
    ) -> None:
        if host not in _ALLOWED_HOSTS:
            raise ValueError("host must be 127.0.0.1 or ::1")
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        super().__init__(
            control_frame_limit=control_frame_limit,
            result_frame_limit=result_frame_limit,
            timeout=timeout,
            max_pending_handshakes=max_pending_handshakes,
        )
        self.descriptor_path = Path(descriptor_path).expanduser().resolve()
        self.host = host
        self.port = port
        self._owned_token: str | None = None

    async def start(self, handler: RequestHandler) -> EndpointDescriptor:
        if self.is_running:
            raise RuntimeError("transport is already running")
        self._handler = handler
        token = secrets.token_urlsafe(48)
        self._expected_auth_token = token
        self._owned_token = token
        family = socket.AF_INET6 if self.host == "::1" else socket.AF_INET
        try:
            self._server = await asyncio.start_server(
                self._accept_stream,
                host=self.host,
                port=self.port,
                family=family,
            )
            listening_socket = self._server.sockets[0]
            socket_name = listening_socket.getsockname()
            effective_port = cast(int, socket_name[1])
            descriptor = EndpointDescriptor(
                transport=TransportKind.TCP,
                host=self.host,
                port=effective_port,
                auth_token=token,
                server_pid=os.getpid(),
            )
            write_endpoint_descriptor(self.descriptor_path, descriptor)
            self._descriptor = descriptor
            return descriptor
        except ProtocolError:
            await super().close()
            remove_endpoint_descriptor(self.descriptor_path, expected_token=token)
            self._owned_token = None
            raise
        except (OSError, ValueError) as exc:
            await super().close()
            remove_endpoint_descriptor(self.descriptor_path, expected_token=token)
            self._owned_token = None
            raise ProtocolError(
                ProtocolErrorCode.ENDPOINT_UNAVAILABLE,
                "Could not start the loopback TCP endpoint.",
            ) from exc

    async def request(self, envelope: Envelope) -> Envelope:
        descriptor = read_endpoint_descriptor(self.descriptor_path)
        if descriptor.transport is not TransportKind.TCP:
            raise ProtocolError(
                ProtocolErrorCode.ENDPOINT_UNAVAILABLE,
                "Endpoint descriptor is not a TCP endpoint.",
            )
        assert descriptor.host is not None
        assert descriptor.port is not None
        assert descriptor.auth_token is not None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_connection(
                    descriptor.host,
                    descriptor.port,
                    family=socket.AF_INET6 if descriptor.host == "::1" else socket.AF_INET,
                )
            return await self._exchange(
                reader,
                writer,
                envelope,
                auth_token=descriptor.auth_token,
            )
        except ProtocolError:
            raise
        except (TimeoutError, OSError, ConnectionError) as exc:
            raise ProtocolError(
                ProtocolErrorCode.CONNECTION_FAILED,
                "Could not connect to the loopback TCP endpoint.",
            ) from exc

    async def close(self) -> None:
        token = self._owned_token
        await super().close()
        if token is not None:
            remove_endpoint_descriptor(self.descriptor_path, expected_token=token)
        self._owned_token = None
        self._descriptor = None

    def _peer_is_allowed(self, writer: asyncio.StreamWriter) -> bool:
        peer = writer.get_extra_info("peername")
        if not isinstance(peer, tuple) or not peer:
            return False
        try:
            return ipaddress.ip_address(str(peer[0])).is_loopback
        except ValueError:
            return False


__all__ = ["LoopbackTcpTransport"]
