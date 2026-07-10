"""Transport-neutral gateway used by MCP tool handlers."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from diagnose.config import (
    default_endpoint_descriptor_path,
    default_unix_socket_path,
    resolve_ipc_endpoint,
)
from diagnose.domain import DiagnoseError, ErrorCode, NormalizedError
from diagnose.ipc import (
    PROTOCOL_ERROR,
    Envelope,
    LocalIpcTransport,
    LoopbackTcpTransport,
    ProtocolError,
    ProtocolErrorCode,
    UnixDomainSocketTransport,
    error_from_envelope,
)


class Gateway(Protocol):
    async def request(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]: ...


class OfflineGateway:
    async def request(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        del message_type, payload
        raise DiagnoseError(
            ErrorCode.TERMINAL_SERVER_OFFLINE,
            "The Diagnose Terminal Server is offline.",
            next_step="Start it in a visible terminal with 'diagnose-terminal start'.",
            retryable=True,
        )


class IpcGateway:
    """Open one authenticated local IPC connection for each MCP tool call."""

    def __init__(self, endpoint: str | Path | None = None) -> None:
        configured = str(endpoint) if endpoint is not None else resolve_ipc_endpoint()
        self._transport: LocalIpcTransport
        if os.name == "nt":
            descriptor = Path(configured) if configured else default_endpoint_descriptor_path()
            self._transport = LoopbackTcpTransport(descriptor)
        else:
            socket_path = Path(configured) if configured else default_unix_socket_path()
            self._transport = UnixDomainSocketTransport(socket_path)

    async def request(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._transport.request(
                Envelope(message_type=message_type, payload=payload)
            )
        except ProtocolError as exc:
            raise _diagnose_error_from_protocol(exc) from exc
        if response.message_type == PROTOCOL_ERROR:
            raise _diagnose_error_from_protocol(error_from_envelope(response))
        public_error = response.payload.get("error")
        if isinstance(public_error, dict):
            normalized = NormalizedError.model_validate(public_error)
            raise DiagnoseError(
                normalized.code,
                normalized.message,
                next_step=normalized.next_step,
                retryable=normalized.retryable,
            )
        return dict(response.payload)


def _diagnose_error_from_protocol(error: ProtocolError) -> DiagnoseError:
    if error.code is ProtocolErrorCode.AUTHENTICATION_FAILED:
        code = ErrorCode.AUTHENTICATION_FAILED
        next_step = "Restart both Diagnose processes to rotate the local IPC token."
    elif error.code is ProtocolErrorCode.UNSUPPORTED_PROTOCOL:
        code = ErrorCode.PROTOCOL_VERSION_MISMATCH
        next_step = "Upgrade the Diagnose package and plugin together."
    elif error.code in {
        ProtocolErrorCode.CONNECTION_CLOSED,
        ProtocolErrorCode.CONNECTION_FAILED,
        ProtocolErrorCode.ENDPOINT_UNAVAILABLE,
    }:
        code = ErrorCode.TERMINAL_SERVER_OFFLINE
        next_step = "Start it in a visible terminal with 'diagnose-terminal start'."
    else:
        code = ErrorCode.CONNECTION_FAILED
        next_step = "Run 'diagnose-terminal doctor' and inspect the local terminal."
    return DiagnoseError(code, error.message, next_step=next_step, retryable=True)


_gateway_factory: Callable[[], Gateway] = IpcGateway


def set_gateway_factory(factory: Callable[[], Gateway]) -> None:
    """Override gateway construction, primarily for tests."""
    global _gateway_factory
    _gateway_factory = factory


def get_gateway() -> Gateway:
    return _gateway_factory()
