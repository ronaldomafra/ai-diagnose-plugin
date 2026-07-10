"""Wire models and helpers for Diagnose's private local IPC protocol."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.alias_generators import to_camel

from diagnose.ipc.errors import ProtocolError, ProtocolErrorCode

PROTOCOL_VERSION = "1.0"
CONNECTION_OPEN = "connection.open"
CONNECTION_OPENED = "connection.opened"
PROTOCOL_ERROR = "protocol.error"

_PROTOCOL_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_ID = Annotated[str, StringConstraints(min_length=5, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]
_MESSAGE_TYPE = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    ),
]


class WireModel(BaseModel):
    """Base for strict models with camelCase JSON field names."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        populate_by_name=True,
        strict=True,
        validate_assignment=True,
    )


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)


def new_message_id() -> str:
    """Return an opaque, non-sequential message identifier."""

    return f"MSG-{uuid.uuid4()}"


def new_correlation_id() -> str:
    """Return an opaque, non-sequential request correlation identifier."""

    return f"REQ-{uuid.uuid4()}"


class Envelope(WireModel):
    """Common envelope for every local IPC message."""

    protocol_version: str = PROTOCOL_VERSION
    message_type: _MESSAGE_TYPE
    message_id: _ID = Field(default_factory=new_message_id)
    correlation_id: _ID = Field(default_factory=new_correlation_id)
    sent_at: datetime = Field(default_factory=utc_now)
    payload: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def validate_protocol_version(cls, value: str) -> str:
        if not _PROTOCOL_VERSION_RE.fullmatch(value):
            raise ValueError("protocol version must use major.minor form")
        return value

    @field_validator("sent_at")
    @classmethod
    def normalize_sent_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("sentAt must include a UTC offset")
        return value.astimezone(UTC)

    def to_wire_dict(self) -> dict[str, JsonValue]:
        """Serialize the envelope using its stable camelCase wire shape."""

        # ``mode=json`` converts datetime into an ISO-8601 string.
        return self.model_dump(mode="json", by_alias=True)

    def to_wire_bytes(self) -> bytes:
        """Serialize deterministically as compact UTF-8 JSON."""

        return json.dumps(
            self.to_wire_dict(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_wire_bytes(cls, data: bytes) -> Self:
        """Parse UTF-8 JSON without leaking invalid input in error messages."""

        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ProtocolError(
                ProtocolErrorCode.INVALID_UTF8,
                "Frame payload is not valid UTF-8.",
            ) from exc

        try:
            json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ProtocolError(
                ProtocolErrorCode.MALFORMED_JSON,
                "Frame payload is not valid JSON.",
            ) from exc

        try:
            # JSON-aware strict validation accepts the standardized datetime
            # string representation while still rejecting type coercion.
            return cls.model_validate_json(data)
        except ValidationError as exc:
            raise ProtocolError(
                ProtocolErrorCode.INVALID_ENVELOPE,
                "Frame payload does not match the envelope schema.",
            ) from exc


class TransportKind(StrEnum):
    UNIX = "unix"
    TCP = "tcp"


class EndpointDescriptor(WireModel):
    """Strict on-disk description of a running local IPC endpoint."""

    protocol_version: str = PROTOCOL_VERSION
    transport: TransportKind
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    socket_path: str | None = None
    auth_token: str | None = Field(default=None, min_length=32, max_length=512, repr=False)
    server_pid: int = Field(gt=0)
    started_at: datetime = Field(default_factory=utc_now)

    @field_validator("protocol_version")
    @classmethod
    def validate_protocol_version(cls, value: str) -> str:
        if not _PROTOCOL_VERSION_RE.fullmatch(value):
            raise ValueError("protocol version must use major.minor form")
        return value

    @field_validator("started_at")
    @classmethod
    def normalize_started_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("startedAt must include a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_transport_fields(self) -> Self:
        if self.transport is TransportKind.UNIX:
            if not self.socket_path or any(
                item is not None for item in (self.host, self.port, self.auth_token)
            ):
                raise ValueError("unix endpoints require only socketPath")
        elif (
            self.host not in {"127.0.0.1", "::1"}
            or self.port is None
            or self.auth_token is None
            or self.socket_path is not None
        ):
            raise ValueError("tcp endpoints require a loopback host, port, and authToken")
        return self

    def to_wire_bytes(self) -> bytes:
        payload = self.model_dump(mode="json", by_alias=True)
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_wire_bytes(cls, data: bytes) -> Self:
        try:
            return cls.model_validate_json(data)
        except (ValidationError, ValueError) as exc:
            raise ProtocolError(
                ProtocolErrorCode.INVALID_ENVELOPE,
                "Endpoint descriptor is invalid.",
            ) from exc


class ConnectionOpenPayload(WireModel):
    supported_protocol_versions: list[str] = Field(min_length=1, max_length=16)
    auth_token: str | None = Field(default=None, min_length=32, max_length=512, repr=False)

    @field_validator("supported_protocol_versions")
    @classmethod
    def validate_versions(cls, versions: list[str]) -> list[str]:
        if any(not _PROTOCOL_VERSION_RE.fullmatch(version) for version in versions):
            raise ValueError("invalid protocol version")
        if len(set(versions)) != len(versions):
            raise ValueError("duplicate protocol version")
        return versions


class ConnectionOpenedPayload(WireModel):
    protocol_version: str

    @field_validator("protocol_version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not _PROTOCOL_VERSION_RE.fullmatch(value):
            raise ValueError("invalid protocol version")
        return value


class ProtocolErrorPayload(WireModel):
    code: ProtocolErrorCode
    message: str = Field(min_length=1, max_length=512)


def parse_payload[T: WireModel](envelope: Envelope, model: type[T]) -> T:
    """Parse a strict payload while keeping raw values out of errors."""

    try:
        # Payload has already crossed a JSON boundary. Re-enter JSON validation
        # so strict enums and temporal types accept their canonical wire strings
        # without enabling Python-side coercion.
        return model.model_validate_json(
            json.dumps(envelope.payload, ensure_ascii=False, allow_nan=False)
        )
    except ValidationError as exc:
        raise ProtocolError(
            ProtocolErrorCode.INVALID_MESSAGE,
            f"Payload for {envelope.message_type} is invalid.",
        ) from exc


def make_connection_open(
    *,
    auth_token: str | None,
    supported_versions: tuple[str, ...] = (PROTOCOL_VERSION,),
) -> Envelope:
    payload = ConnectionOpenPayload(
        supported_protocol_versions=list(supported_versions),
        auth_token=auth_token,
    )
    return Envelope(
        protocol_version=supported_versions[0],
        message_type=CONNECTION_OPEN,
        payload=payload.model_dump(mode="json", by_alias=True),
    )


def make_connection_opened(request: Envelope, protocol_version: str) -> Envelope:
    payload = ConnectionOpenedPayload(protocol_version=protocol_version)
    return Envelope(
        protocol_version=protocol_version,
        message_type=CONNECTION_OPENED,
        correlation_id=request.message_id,
        payload=payload.model_dump(mode="json", by_alias=True),
    )


def make_error_envelope(
    error: ProtocolError,
    *,
    correlation_id: str | None = None,
    protocol_version: str = PROTOCOL_VERSION,
) -> Envelope:
    payload = ProtocolErrorPayload(code=error.code, message=error.message)
    return Envelope(
        protocol_version=protocol_version,
        message_type=PROTOCOL_ERROR,
        correlation_id=correlation_id or new_correlation_id(),
        payload=payload.model_dump(mode="json", by_alias=True),
    )


def error_from_envelope(envelope: Envelope) -> ProtocolError:
    if envelope.message_type != PROTOCOL_ERROR:
        raise ProtocolError(
            ProtocolErrorCode.INVALID_MESSAGE,
            "Expected a protocol error envelope.",
        )
    payload = parse_payload(envelope, ProtocolErrorPayload)
    return ProtocolError(payload.code, payload.message)


def negotiate_protocol(supported_versions: list[str]) -> str:
    """Select the current protocol version or fail on incompatibility."""

    if PROTOCOL_VERSION in supported_versions:
        return PROTOCOL_VERSION
    raise ProtocolError(
        ProtocolErrorCode.UNSUPPORTED_PROTOCOL,
        f"No compatible protocol version; server supports {PROTOCOL_VERSION}.",
    )


__all__ = [
    "CONNECTION_OPEN",
    "CONNECTION_OPENED",
    "PROTOCOL_ERROR",
    "PROTOCOL_VERSION",
    "ConnectionOpenPayload",
    "ConnectionOpenedPayload",
    "EndpointDescriptor",
    "Envelope",
    "ProtocolErrorPayload",
    "TransportKind",
    "WireModel",
    "error_from_envelope",
    "make_connection_open",
    "make_connection_opened",
    "make_error_envelope",
    "negotiate_protocol",
    "new_correlation_id",
    "new_message_id",
    "parse_payload",
    "utc_now",
]
