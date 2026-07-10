"""Unix-domain-socket implementation of local Diagnose IPC."""

from __future__ import annotations

import asyncio
import os
import socket
import stat
from collections.abc import Awaitable, Callable, Coroutine
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, cast

from diagnose.ipc.errors import ProtocolError, ProtocolErrorCode
from diagnose.ipc.framing import CONTROL_FRAME_LIMIT, RESULT_FRAME_LIMIT
from diagnose.ipc.protocol import EndpointDescriptor, Envelope, TransportKind
from diagnose.ipc.transport import (
    DEFAULT_MAX_PENDING_HANDSHAKES,
    LocalIpcTransport,
    RequestHandler,
)


class _StartUnixServer(Protocol):
    def __call__(
        self,
        client_connected_cb: Callable[
            [asyncio.StreamReader, asyncio.StreamWriter],
            Awaitable[None] | None,
        ],
        *,
        path: str,
    ) -> Coroutine[Any, Any, asyncio.AbstractServer]: ...


class _OpenUnixConnection(Protocol):
    def __call__(
        self,
        path: str,
    ) -> Coroutine[Any, Any, tuple[asyncio.StreamReader, asyncio.StreamWriter]]: ...


_start_unix_server = cast(_StartUnixServer, getattr(asyncio, "start_unix_server", None))
_open_unix_connection = cast(
    _OpenUnixConnection,
    getattr(asyncio, "open_unix_connection", None),
)


class UnixDomainSocketTransport(LocalIpcTransport):
    """User-private Unix socket transport."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        control_frame_limit: int = CONTROL_FRAME_LIMIT,
        result_frame_limit: int = RESULT_FRAME_LIMIT,
        timeout: float = 5.0,
        max_pending_handshakes: int = DEFAULT_MAX_PENDING_HANDSHAKES,
    ) -> None:
        super().__init__(
            control_frame_limit=control_frame_limit,
            result_frame_limit=result_frame_limit,
            timeout=timeout,
            max_pending_handshakes=max_pending_handshakes,
        )
        self.socket_path = Path(socket_path).expanduser().resolve()
        self._socket_identity: tuple[int, int] | None = None

    async def start(self, handler: RequestHandler) -> EndpointDescriptor:
        if not hasattr(socket, "AF_UNIX"):
            raise ProtocolError(
                ProtocolErrorCode.ENDPOINT_UNAVAILABLE,
                "Unix domain sockets are not supported on this platform.",
            )
        if self.is_running:
            raise RuntimeError("transport is already running")

        self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self.socket_path.parent, 0o700)
            await self._remove_stale_socket()
            self._handler = handler
            self._expected_auth_token = None
            self._server = await _start_unix_server(
                self._accept_stream,
                path=str(self.socket_path),
            )
            os.chmod(self.socket_path, 0o600)
            socket_stat = self.socket_path.stat()
            self._socket_identity = (socket_stat.st_dev, socket_stat.st_ino)
            self._descriptor = EndpointDescriptor(
                transport=TransportKind.UNIX,
                socket_path=str(self.socket_path),
                server_pid=os.getpid(),
            )
            return self._descriptor
        except ProtocolError:
            self._handler = None
            raise
        except (OSError, ValueError) as exc:
            await super().close()
            self._remove_owned_socket()
            raise ProtocolError(
                ProtocolErrorCode.ENDPOINT_UNAVAILABLE,
                "Could not start the Unix domain socket endpoint.",
            ) from exc

    async def request(self, envelope: Envelope) -> Envelope:
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await _open_unix_connection(str(self.socket_path))
            return await self._exchange(reader, writer, envelope, auth_token=None)
        except ProtocolError:
            raise
        except (TimeoutError, OSError, ConnectionError) as exc:
            raise ProtocolError(
                ProtocolErrorCode.CONNECTION_FAILED,
                "Could not connect to the Unix domain socket endpoint.",
            ) from exc

    async def close(self) -> None:
        await super().close()
        self._remove_owned_socket()
        self._descriptor = None

    async def _remove_stale_socket(self) -> None:
        try:
            path_stat = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(path_stat.st_mode):
            raise ProtocolError(
                ProtocolErrorCode.ENDPOINT_IN_USE,
                "Unix socket path exists and is not a socket.",
            )

        try:
            _reader, writer = await asyncio.wait_for(
                _open_unix_connection(str(self.socket_path)),
                timeout=min(self.timeout, 0.5),
            )
        except (ConnectionRefusedError, FileNotFoundError, TimeoutError, OSError):
            self.socket_path.unlink(missing_ok=True)
            return
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        raise ProtocolError(
            ProtocolErrorCode.ENDPOINT_IN_USE,
            "Unix socket endpoint is already accepting connections.",
        )

    def _remove_owned_socket(self) -> None:
        identity, self._socket_identity = self._socket_identity, None
        if identity is None:
            return
        try:
            path_stat = self.socket_path.lstat()
            if (path_stat.st_dev, path_stat.st_ino) == identity:
                self.socket_path.unlink()
        except FileNotFoundError:
            return


__all__ = ["UnixDomainSocketTransport"]
