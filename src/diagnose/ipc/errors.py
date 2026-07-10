"""Normalized errors for the local Diagnose IPC protocol."""

from __future__ import annotations

from enum import StrEnum
from typing import final


@final
class ProtocolErrorCode(StrEnum):
    """Stable, safe-to-return protocol error codes."""

    CONNECTION_CLOSED = "CONNECTION_CLOSED"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    MALFORMED_FRAME = "MALFORMED_FRAME"
    FRAME_TOO_LARGE = "FRAME_TOO_LARGE"
    INVALID_UTF8 = "INVALID_UTF8"
    MALFORMED_JSON = "MALFORMED_JSON"
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    INVALID_MESSAGE = "INVALID_MESSAGE"
    UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    ENDPOINT_UNAVAILABLE = "ENDPOINT_UNAVAILABLE"
    ENDPOINT_IN_USE = "ENDPOINT_IN_USE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    HANDLER_ERROR = "HANDLER_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ProtocolError(Exception):
    """An IPC failure whose message is safe to expose to a local client.

    Raw payloads, authentication tokens, and exception reprs must never be placed
    in ``message``.
    """

    def __init__(
        self,
        code: ProtocolErrorCode,
        message: str,
        *,
        fatal: bool = True,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.fatal = fatal

    def __str__(self) -> str:
        return f"{self.code.value}: {self.message}"


__all__ = ["ProtocolError", "ProtocolErrorCode"]
