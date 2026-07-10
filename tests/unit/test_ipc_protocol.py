from __future__ import annotations

import json
from datetime import UTC

import pytest
from pydantic import ValidationError

from diagnose.ipc import (
    EndpointDescriptor,
    Envelope,
    ProtocolError,
    ProtocolErrorCode,
    TransportKind,
)


def test_envelope_uses_strict_camel_case_wire_shape_and_utc() -> None:
    envelope = Envelope(message_type="server.info", payload={"ready": True})

    raw = json.loads(envelope.to_wire_bytes())

    assert set(raw) == {
        "protocolVersion",
        "messageType",
        "messageId",
        "correlationId",
        "sentAt",
        "payload",
    }
    assert raw["protocolVersion"] == "1.0"
    assert raw["messageId"].startswith("MSG-")
    assert raw["correlationId"].startswith("REQ-")
    assert raw["sentAt"].endswith("Z")
    assert envelope.sent_at.tzinfo is UTC
    assert Envelope.from_wire_bytes(envelope.to_wire_bytes()) == envelope


def test_envelope_serialization_is_deterministic() -> None:
    envelope = Envelope(message_type="targets.list", payload={"z": 1, "a": [True, None]})

    first = envelope.to_wire_bytes()
    second = envelope.to_wire_bytes()

    assert first == second
    assert first.startswith(b'{"correlationId"')


def test_envelope_rejects_unknown_fields_and_python_coercion() -> None:
    with pytest.raises(ValidationError):
        Envelope.model_validate(
            {
                "messageType": "server.info",
                "payload": {},
                "unknown": "unsafe",
            }
        )

    with pytest.raises(ValidationError):
        Envelope(message_type="server.info", payload={}, protocol_version=1.0)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("wire", "code"),
    [
        (b"\xff", ProtocolErrorCode.INVALID_UTF8),
        (b"{", ProtocolErrorCode.MALFORMED_JSON),
        (b"{}", ProtocolErrorCode.INVALID_ENVELOPE),
        (
            b'{"protocolVersion":"1.0","messageType":"server.info",'
            b'"messageId":"MSG-a","correlationId":"REQ-a",'
            b'"sentAt":"2026-07-10T12:00:00Z","payload":{},"extra":true}',
            ProtocolErrorCode.INVALID_ENVELOPE,
        ),
    ],
)
def test_invalid_envelope_errors_are_normalized(
    wire: bytes,
    code: ProtocolErrorCode,
) -> None:
    with pytest.raises(ProtocolError) as caught:
        Envelope.from_wire_bytes(wire)

    assert caught.value.code is code
    decoded = wire.decode("utf-8", errors="ignore")
    if decoded:
        assert decoded not in str(caught.value)


def test_endpoint_descriptor_requires_transport_specific_fields() -> None:
    unix = EndpointDescriptor(
        transport=TransportKind.UNIX,
        socket_path="/tmp/diagnose.sock",
        server_pid=42,
    )
    tcp = EndpointDescriptor(
        transport=TransportKind.TCP,
        host="127.0.0.1",
        port=12345,
        auth_token="x" * 32,
        server_pid=42,
    )

    assert unix.auth_token is None
    assert tcp.socket_path is None
    assert "x" * 32 not in repr(tcp)

    with pytest.raises(ValidationError):
        EndpointDescriptor(
            transport=TransportKind.TCP,
            host="0.0.0.0",
            port=12345,
            auth_token="x" * 32,
            server_pid=42,
        )
