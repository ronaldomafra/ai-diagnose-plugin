"""Shared asyncio transport contract and connection protocol."""

from __future__ import annotations

import asyncio
import hmac
import inspect
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from contextlib import suppress

from diagnose.ipc.errors import ProtocolError, ProtocolErrorCode
from diagnose.ipc.framing import (
    CONTROL_FRAME_LIMIT,
    RESULT_FRAME_LIMIT,
    read_envelope,
    write_envelope,
)
from diagnose.ipc.protocol import (
    CONNECTION_OPEN,
    CONNECTION_OPENED,
    PROTOCOL_ERROR,
    PROTOCOL_VERSION,
    ConnectionOpenedPayload,
    ConnectionOpenPayload,
    EndpointDescriptor,
    Envelope,
    error_from_envelope,
    make_connection_open,
    make_connection_opened,
    make_error_envelope,
    negotiate_protocol,
    parse_payload,
)

type HandlerResult = Envelope
type RequestHandler = Callable[[Envelope], Awaitable[HandlerResult] | HandlerResult]

DEFAULT_MAX_PENDING_HANDSHAKES = 32


class LocalIpcTransport(ABC):
    """Common server/client interface for a local IPC endpoint."""

    def __init__(
        self,
        *,
        control_frame_limit: int = CONTROL_FRAME_LIMIT,
        result_frame_limit: int = RESULT_FRAME_LIMIT,
        timeout: float = 5.0,
        max_pending_handshakes: int = DEFAULT_MAX_PENDING_HANDSHAKES,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if not 0 < control_frame_limit <= CONTROL_FRAME_LIMIT:
            raise ValueError(f"control_frame_limit must be between 1 and {CONTROL_FRAME_LIMIT}")
        if not 0 < result_frame_limit <= RESULT_FRAME_LIMIT:
            raise ValueError(f"result_frame_limit must be between 1 and {RESULT_FRAME_LIMIT}")
        if (
            not isinstance(max_pending_handshakes, int)
            or isinstance(max_pending_handshakes, bool)
            or max_pending_handshakes <= 0
        ):
            raise ValueError("max_pending_handshakes must be a positive integer")
        self.control_frame_limit = control_frame_limit
        self.result_frame_limit = result_frame_limit
        self.timeout = timeout
        self.max_pending_handshakes = max_pending_handshakes
        self._server: asyncio.AbstractServer | None = None
        self._handler: RequestHandler | None = None
        self._connections: set[asyncio.StreamWriter] = set()
        self._pending_handshakes: set[asyncio.StreamWriter] = set()
        self._descriptor: EndpointDescriptor | None = None
        self._expected_auth_token: str | None = None

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._server.is_serving()

    @property
    def endpoint_descriptor(self) -> EndpointDescriptor:
        if self._descriptor is None:
            raise RuntimeError("transport has not been started")
        return self._descriptor

    @abstractmethod
    async def start(self, handler: RequestHandler) -> EndpointDescriptor:
        """Start accepting requests and return the effective endpoint."""

    @abstractmethod
    async def request(self, envelope: Envelope) -> Envelope:
        """Perform one authenticated handshake and one request."""

    async def close(self) -> None:
        """Stop the server and close all streams accepted by it."""

        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()
        connections = tuple(self._connections)
        for writer in connections:
            writer.close()
        if connections:
            await asyncio.gather(
                *(self._wait_closed(writer) for writer in connections),
                return_exceptions=True,
            )
        self._connections.clear()
        self._pending_handshakes.clear()
        self._handler = None
        self._expected_auth_token = None

    async def stop(self) -> None:
        """Alias used by command-oriented callers."""

        await self.close()

    async def _accept_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._connections.add(writer)
        try:
            if not self._peer_is_allowed(writer):
                return
            # This check and insertion happen before the first await, so callbacks
            # accepted by the same event loop cannot race past the configured cap.
            if len(self._pending_handshakes) >= self.max_pending_handshakes:
                return
            self._pending_handshakes.add(writer)
            await self._serve_stream(reader, writer)
        except (TimeoutError, ConnectionError, OSError):
            # Timeouts and abrupt disconnects are intentionally silent. In
            # particular, a pre-authentication timeout must not become an oracle.
            return
        finally:
            self._pending_handshakes.discard(writer)
            self._connections.discard(writer)
            writer.close()
            await self._wait_closed(writer)

    def _peer_is_allowed(self, writer: asyncio.StreamWriter) -> bool:
        del writer
        return True

    async def _serve_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        correlation_id: str | None = None
        negotiated_version = PROTOCOL_VERSION
        try:
            opening = await self._read_envelope(reader, max_size=self.control_frame_limit)
            correlation_id = opening.message_id
            if opening.message_type != CONNECTION_OPEN:
                raise ProtocolError(
                    ProtocolErrorCode.INVALID_MESSAGE,
                    "The first message must be connection.open.",
                )
            open_payload = parse_payload(opening, ConnectionOpenPayload)
            self._authenticate(open_payload.auth_token)
            self._pending_handshakes.discard(writer)
            negotiated_version = negotiate_protocol(open_payload.supported_protocol_versions)
            await self._write_envelope(
                writer,
                make_connection_opened(opening, negotiated_version),
                max_size=self.control_frame_limit,
            )

            request = await self._read_envelope(reader, max_size=self.control_frame_limit)
            correlation_id = request.message_id
            if request.protocol_version != negotiated_version:
                raise ProtocolError(
                    ProtocolErrorCode.UNSUPPORTED_PROTOCOL,
                    "Message protocolVersion differs from the negotiated version.",
                )
            if request.message_type in {CONNECTION_OPEN, CONNECTION_OPENED, PROTOCOL_ERROR}:
                raise ProtocolError(
                    ProtocolErrorCode.INVALID_MESSAGE,
                    "Message type is not valid for an application request.",
                )
            if self._handler is None:
                raise ProtocolError(
                    ProtocolErrorCode.INTERNAL_ERROR,
                    "Request handler is unavailable.",
                )

            try:
                response_or_awaitable = self._handler(request)
                response = (
                    await self._await_handler(response_or_awaitable)
                    if inspect.isawaitable(response_or_awaitable)
                    else response_or_awaitable
                )
                if not isinstance(response, Envelope):
                    raise TypeError("request handler must return Envelope")
            except ProtocolError:
                raise
            except Exception as exc:
                raise ProtocolError(
                    ProtocolErrorCode.HANDLER_ERROR,
                    "Request handler failed.",
                ) from exc

            response = response.model_copy(
                update={
                    "protocol_version": negotiated_version,
                    "correlation_id": request.message_id,
                }
            )
            await self._write_envelope(writer, response, max_size=self.result_frame_limit)
        except ProtocolError as error:
            # Invalid TCP credentials are deliberately answered with an immediate
            # close so the token cannot become an oracle.
            if error.code is ProtocolErrorCode.AUTHENTICATION_FAILED:
                return
            await self._send_protocol_error(
                writer,
                error,
                correlation_id=correlation_id,
                protocol_version=negotiated_version,
            )

    def _authenticate(self, received_token: str | None) -> None:
        expected = self._expected_auth_token
        if expected is None:
            if received_token is not None:
                raise ProtocolError(
                    ProtocolErrorCode.AUTHENTICATION_FAILED,
                    "Authentication failed.",
                )
            return
        if received_token is None or not hmac.compare_digest(expected, received_token):
            raise ProtocolError(
                ProtocolErrorCode.AUTHENTICATION_FAILED,
                "Authentication failed.",
            )

    async def _send_protocol_error(
        self,
        writer: asyncio.StreamWriter,
        error: ProtocolError,
        *,
        correlation_id: str | None,
        protocol_version: str,
    ) -> None:
        with suppress(ProtocolError, ConnectionError, BrokenPipeError):
            await self._write_envelope(
                writer,
                make_error_envelope(
                    error,
                    correlation_id=correlation_id,
                    protocol_version=protocol_version,
                ),
                max_size=self.control_frame_limit,
            )

    async def _exchange(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        request: Envelope,
        *,
        auth_token: str | None,
    ) -> Envelope:
        try:
            opening = make_connection_open(auth_token=auth_token)
            await self._write_envelope(writer, opening, max_size=self.control_frame_limit)
            try:
                opened = await self._read_envelope(reader, max_size=self.control_frame_limit)
            except ProtocolError as error:
                if auth_token is not None and error.code is ProtocolErrorCode.CONNECTION_CLOSED:
                    raise ProtocolError(
                        ProtocolErrorCode.AUTHENTICATION_FAILED,
                        "Authentication failed.",
                    ) from error
                raise
            if opened.message_type == PROTOCOL_ERROR:
                raise error_from_envelope(opened)
            if (
                opened.message_type != CONNECTION_OPENED
                or opened.correlation_id != opening.message_id
            ):
                raise ProtocolError(
                    ProtocolErrorCode.INVALID_MESSAGE,
                    "Server returned an invalid handshake response.",
                )
            opened_payload = parse_payload(opened, ConnectionOpenedPayload)
            if opened_payload.protocol_version != PROTOCOL_VERSION:
                raise ProtocolError(
                    ProtocolErrorCode.UNSUPPORTED_PROTOCOL,
                    "Server selected an unsupported protocol version.",
                )

            await self._write_envelope(writer, request, max_size=self.control_frame_limit)
            response = await self._read_envelope(reader, max_size=self.result_frame_limit)
            if response.message_type == PROTOCOL_ERROR:
                raise error_from_envelope(response)
            if response.protocol_version != opened_payload.protocol_version:
                raise ProtocolError(
                    ProtocolErrorCode.UNSUPPORTED_PROTOCOL,
                    "Response protocolVersion differs from the negotiated version.",
                )
            if response.correlation_id != request.message_id:
                raise ProtocolError(
                    ProtocolErrorCode.INVALID_MESSAGE,
                    "Response correlationId does not match the request.",
                )
            return response
        finally:
            writer.close()
            await self._wait_closed(writer)

    async def _read_envelope(
        self,
        reader: asyncio.StreamReader,
        *,
        max_size: int,
    ) -> Envelope:
        async with asyncio.timeout(self.timeout):
            return await read_envelope(reader, max_size=max_size)

    async def _write_envelope(
        self,
        writer: asyncio.StreamWriter,
        envelope: Envelope,
        *,
        max_size: int,
    ) -> None:
        async with asyncio.timeout(self.timeout):
            await write_envelope(writer, envelope, max_size=max_size)

    async def _await_handler(self, response: Awaitable[HandlerResult]) -> HandlerResult:
        async with asyncio.timeout(self.timeout):
            return await response

    async def _wait_closed(self, writer: asyncio.StreamWriter) -> None:
        with suppress(Exception):
            async with asyncio.timeout(self.timeout):
                await writer.wait_closed()


__all__ = [
    "DEFAULT_MAX_PENDING_HANDSHAKES",
    "LocalIpcTransport",
    "RequestHandler",
]
