"""Core Diagnose domain contracts independent from MCP and executor SDKs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import Field, JsonValue, field_validator, model_validator

from .base import DomainModel, FrozenDomainModel
from .errors import NormalizedError
from .hashing import canonical_sha256
from .states import ActionState, DiagnosisState, RiskClass


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_request_id() -> str:
    return f"REQ-{uuid4().hex}"


def new_session_id() -> str:
    return f"DIAG-{uuid4().hex}"


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(UTC)


class CommandOperation(FrozenDomainModel):
    """Resolved argv operation; this is a plan contract, not a shell executor."""

    type: Literal["command"] = "command"
    executable: str = Field(min_length=1, max_length=4096)
    arguments: tuple[str, ...] = ()
    working_directory: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    stdin_sha256: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class FakeOperation(FrozenDomainModel):
    """M0 test-only operation used to exercise approval without target access."""

    type: Literal["fake"] = "fake"
    output: JsonValue = None
    delay_ms: int = Field(default=0, ge=0, le=60_000)
    fail: bool = False


ExecutionOperation = Annotated[CommandOperation | FakeOperation, Field(discriminator="type")]


class ExecutionConstraints(FrozenDomainModel):
    timeout_seconds: int = Field(default=20, ge=1, le=3600)
    max_output_bytes: int = Field(default=262_144, ge=1, le=8 * 1024 * 1024)
    max_output_lines: int | None = Field(default=None, ge=1, le=1_000_000)


class ExecutionPlan(FrozenDomainModel):
    request_id: str = Field(min_length=5, max_length=200)
    session_id: str = Field(min_length=5, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=100)
    risk: RiskClass
    reason: str = Field(min_length=1, max_length=2000)
    executor: str = Field(min_length=1, max_length=100)
    operation: ExecutionOperation
    constraints: ExecutionConstraints = Field(default_factory=ExecutionConstraints)
    policy_version: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    target_version: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    action_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")

    def hash_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude={"action_hash"})

    def calculate_hash(self) -> str:
        """Calculate the immutable approval hash, excluding actionHash itself."""

        return canonical_sha256(self.hash_payload())

    def with_calculated_hash(self) -> ExecutionPlan:
        return self.model_copy(update={"action_hash": self.calculate_hash()})

    def verify_hash(self) -> bool:
        return self.action_hash is not None and self.action_hash == self.calculate_hash()


class ActionReceipt(DomainModel):
    request_id: str = Field(min_length=5, max_length=200)
    session_id: str = Field(min_length=5, max_length=200)
    status: ActionState
    risk: RiskClass
    summary: str = Field(min_length=1, max_length=2000)
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=100)
    target_id: str | None = Field(default=None, max_length=200)
    created_at: datetime
    expires_at: datetime | None = None

    _utc_created = field_validator("created_at")(_require_utc)
    _utc_expires = field_validator("expires_at")(
        lambda value: _require_utc(value) if value is not None else None
    )

    @model_validator(mode="after")
    def expiration_follows_creation(self) -> ActionReceipt:
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("expiresAt must be later than createdAt")
        return self

    @classmethod
    def pending(
        cls,
        *,
        session_id: str,
        risk: RiskClass,
        summary: str,
        tool: str,
        target_id: str,
        approval_timeout_seconds: int = 300,
        request_id: str | None = None,
        now: datetime | None = None,
    ) -> ActionReceipt:
        created_at = (now or utc_now()).astimezone(UTC)
        return cls(
            request_id=request_id or new_request_id(),
            session_id=session_id,
            status=ActionState.PENDING_APPROVAL,
            risk=risk,
            summary=summary,
            tool=tool,
            target_id=target_id,
            created_at=created_at,
            expires_at=created_at + timedelta(seconds=approval_timeout_seconds),
        )


class ActionRecord(ActionReceipt):
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: NormalizedError | None = None

    _utc_updated = field_validator("updated_at")(_require_utc)
    _utc_started = field_validator("started_at")(
        lambda value: _require_utc(value) if value is not None else None
    )
    _utc_finished = field_validator("finished_at")(
        lambda value: _require_utc(value) if value is not None else None
    )

    def receipt(self) -> ActionReceipt:
        fields = ActionReceipt.model_fields
        return ActionReceipt.model_validate(
            self.model_dump(include=set(fields), mode="python", by_alias=False)
        )


class ActionResult(DomainModel):
    request_id: str = Field(min_length=5, max_length=200)
    status: ActionState
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=100)
    target_id: str | None = Field(default=None, max_length=200)
    started_at: datetime | None = None
    finished_at: datetime
    duration_ms: int = Field(ge=0)
    data: JsonValue = None
    warnings: list[str] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
    truncated: bool = False
    error: NormalizedError | None = None

    _utc_started = field_validator("started_at")(
        lambda value: _require_utc(value) if value is not None else None
    )
    _utc_finished = field_validator("finished_at")(_require_utc)

    @model_validator(mode="after")
    def result_is_terminal(self) -> ActionResult:
        if self.status not in {
            ActionState.COMPLETED,
            ActionState.FAILED,
            ActionState.CANCELLED,
        }:
            raise ValueError("result status must be COMPLETED, FAILED, or CANCELLED")
        return self


class DiagnosisSession(DomainModel):
    session_id: str = Field(min_length=5, max_length=200)
    state: DiagnosisState = DiagnosisState.COLLECTING
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    _utc_created = field_validator("created_at")(_require_utc)
    _utc_updated = field_validator("updated_at")(_require_utc)
    _utc_closed = field_validator("closed_at")(
        lambda value: _require_utc(value) if value is not None else None
    )

    @classmethod
    def create(
        cls,
        *,
        session_id: str | None = None,
        metadata: dict[str, JsonValue] | None = None,
        now: datetime | None = None,
    ) -> DiagnosisSession:
        timestamp = (now or utc_now()).astimezone(UTC)
        return cls(
            session_id=session_id or new_session_id(),
            created_at=timestamp,
            updated_at=timestamp,
            metadata=metadata or {},
        )
