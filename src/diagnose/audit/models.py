"""Audit event and verification contracts."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import Field, JsonValue, field_validator

from diagnose.domain import DomainModel


class AuditEvent(DomainModel):
    event_type: str = Field(min_length=1, max_length=200, pattern=r"^[a-z][a-z0-9_.-]*$")
    occurred_at: datetime
    request_id: str | None = None
    session_id: str | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def timestamp_has_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurredAt must include a UTC offset")
        return value.astimezone(UTC)


class AuditVerification(DomainModel):
    valid: bool
    entries_checked: int = Field(ge=0)
    sqlite_integrity: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
