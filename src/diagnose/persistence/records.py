"""Storage-specific records that do not leak SQLite details to callers."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, JsonValue, field_validator

from diagnose.domain import (
    ActionRecord,
    ActionResult,
    DomainModel,
    ExecutionPlan,
    NormalizedError,
    canonical_sha256,
)

AUDIT_GENESIS_HASH = "sha256:" + "0" * 64


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include an offset")
    return value.astimezone(UTC)


class ActionEvent(DomainModel):
    event_id: int = Field(ge=1)
    request_id: str
    from_state: str | None = None
    to_state: str
    occurred_at: datetime
    detail: dict[str, JsonValue] = Field(default_factory=dict)

    _utc_occurred = field_validator("occurred_at")(_require_utc)


class StoredAuditEntry(DomainModel):
    sequence: int = Field(ge=1)
    occurred_at: datetime
    event_type: str = Field(min_length=1, max_length=200)
    request_id: str | None = None
    session_id: str | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)
    previous_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    _utc_occurred = field_validator("occurred_at")(_require_utc)

    def hash_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude={"entry_hash"})

    def calculate_hash(self) -> str:
        return canonical_sha256(self.hash_payload())

    def with_calculated_hash(self) -> StoredAuditEntry:
        return self.model_copy(update={"entry_hash": self.calculate_hash()})


class StartActionOutcome(StrEnum):
    STARTED = "STARTED"
    EXPIRED = "EXPIRED"
    CONFIGURATION_CHANGED = "CONFIGURATION_CHANGED"
    SESSION_CLOSED = "SESSION_CLOSED"
    NON_PENDING = "NON_PENDING"
    NOT_FOUND = "NOT_FOUND"
    PLAN_MISMATCH = "PLAN_MISMATCH"


class StartActionResult(DomainModel):
    outcome: StartActionOutcome
    action: ActionRecord | None = None
    plan: ExecutionPlan | None = None
    error: NormalizedError | None = None
    audit_entry: StoredAuditEntry | None = None


class FinalizedAction(DomainModel):
    action: ActionRecord
    result: ActionResult
    result_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audit_entry: StoredAuditEntry


class KnownHostFingerprint(DomainModel):
    target_id: str
    hostname: str
    port: int = Field(ge=1, le=65535)
    fingerprint: str
    created_at: datetime
    updated_at: datetime

    _utc_created = field_validator("created_at")(_require_utc)
    _utc_updated = field_validator("updated_at")(_require_utc)
