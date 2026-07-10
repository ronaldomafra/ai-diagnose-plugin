"""Secure local asyncio IPC used between Diagnose's MCP and Terminal servers."""

from diagnose.ipc.descriptor import (
    endpoint_permissions_are_private,
    read_endpoint_descriptor,
    remove_endpoint_descriptor,
    write_endpoint_descriptor,
)
from diagnose.ipc.errors import ProtocolError, ProtocolErrorCode
from diagnose.ipc.framing import (
    CONTROL_FRAME_LIMIT,
    GLOBAL_FRAME_LIMIT,
    RESULT_FRAME_LIMIT,
    pack_frame,
    read_envelope,
    read_frame,
    write_envelope,
    write_frame,
)
from diagnose.ipc.loopback_tcp import LoopbackTcpTransport
from diagnose.ipc.protocol import (
    CONNECTION_OPEN,
    CONNECTION_OPENED,
    PROTOCOL_ERROR,
    PROTOCOL_VERSION,
    ConnectionOpenedPayload,
    ConnectionOpenPayload,
    EndpointDescriptor,
    Envelope,
    ProtocolErrorPayload,
    TransportKind,
    WireModel,
    error_from_envelope,
    make_error_envelope,
    new_correlation_id,
    new_message_id,
    parse_payload,
    utc_now,
)
from diagnose.ipc.transport import (
    DEFAULT_MAX_PENDING_HANDSHAKES,
    LocalIpcTransport,
    RequestHandler,
)
from diagnose.ipc.unix_socket import UnixDomainSocketTransport

__all__ = [
    "CONNECTION_OPEN",
    "CONNECTION_OPENED",
    "CONTROL_FRAME_LIMIT",
    "DEFAULT_MAX_PENDING_HANDSHAKES",
    "GLOBAL_FRAME_LIMIT",
    "PROTOCOL_ERROR",
    "PROTOCOL_VERSION",
    "RESULT_FRAME_LIMIT",
    "ConnectionOpenPayload",
    "ConnectionOpenedPayload",
    "EndpointDescriptor",
    "Envelope",
    "LocalIpcTransport",
    "LoopbackTcpTransport",
    "ProtocolError",
    "ProtocolErrorCode",
    "ProtocolErrorPayload",
    "RequestHandler",
    "TransportKind",
    "UnixDomainSocketTransport",
    "WireModel",
    "endpoint_permissions_are_private",
    "error_from_envelope",
    "make_error_envelope",
    "new_correlation_id",
    "new_message_id",
    "pack_frame",
    "parse_payload",
    "read_endpoint_descriptor",
    "read_envelope",
    "read_frame",
    "remove_endpoint_descriptor",
    "utc_now",
    "write_endpoint_descriptor",
    "write_envelope",
    "write_frame",
]
