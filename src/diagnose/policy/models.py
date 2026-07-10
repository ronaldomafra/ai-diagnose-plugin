"""Strict policy configuration and evaluation contracts."""

from __future__ import annotations

from typing import Any

from pydantic import Field, JsonValue, model_validator

from diagnose.domain import DomainModel, FrozenDomainModel, PolicyDecision


class PolicyLimits(FrozenDomainModel):
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    max_output_bytes: int | None = Field(default=None, ge=1, le=8 * 1024 * 1024)
    max_lines: int | None = Field(default=None, ge=1, le=1_000_000)
    max_rows: int | None = Field(default=None, ge=1, le=1_000_000)
    approval_timeout_seconds: int | None = Field(default=None, ge=30, le=3600)


class ToolPolicy(DomainModel):
    decision: PolicyDecision = PolicyDecision.DENY
    timeout_seconds: int | None = Field(default=None, ge=1, le=3600)
    max_output_bytes: int | None = Field(default=None, ge=1, le=8 * 1024 * 1024)
    max_lines: int | None = Field(default=None, ge=1, le=1_000_000)
    max_rows: int | None = Field(default=None, ge=1, le=1_000_000)
    approval_timeout_seconds: int | None = Field(default=None, ge=30, le=3600)
    allowed_services: list[str] = Field(default_factory=list)
    allowed_executables: list[str] = Field(default_factory=list)
    constraints: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def automatic_is_reserved(self) -> ToolPolicy:
        if self.decision is PolicyDecision.ALLOW_AUTOMATIC:
            raise ValueError("ALLOW_AUTOMATIC is reserved and cannot be enabled in v1")
        return self

    def limits(self) -> PolicyLimits:
        return PolicyLimits(
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            max_lines=self.max_lines,
            max_rows=self.max_rows,
            approval_timeout_seconds=self.approval_timeout_seconds,
        )


class PolicyDefinition(DomainModel):
    targets: list[str] = Field(default_factory=list)
    default_decision: PolicyDecision = PolicyDecision.DENY
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)

    @model_validator(mode="after")
    def automatic_is_reserved(self) -> PolicyDefinition:
        if self.default_decision is PolicyDecision.ALLOW_AUTOMATIC:
            raise ValueError("ALLOW_AUTOMATIC is reserved and cannot be enabled in v1")
        if self.default_decision is not PolicyDecision.DENY:
            raise ValueError("defaultDecision must be DENY; tools must be allowed explicitly")
        return self


class PolicySet(DomainModel):
    policies: dict[str, PolicyDefinition] = Field(default_factory=dict)


class PolicyEvaluation(FrozenDomainModel):
    decision: PolicyDecision
    policy_ref: str | None = None
    policy_version: str
    limits: PolicyLimits = Field(default_factory=PolicyLimits)
    allowed_services: tuple[str, ...] = ()
    allowed_executables: tuple[str, ...] = ()
    constraints: dict[str, JsonValue] = Field(default_factory=dict)
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision is PolicyDecision.ALLOW_WITH_APPROVAL


def merge_limits(*, global_limits: PolicyLimits, tool: ToolPolicy | None) -> PolicyLimits:
    """Apply server-side minima for a policy rule without widening global limits."""

    if tool is None:
        return global_limits

    values: dict[str, Any] = {}
    for field_name in PolicyLimits.model_fields:
        global_value = getattr(global_limits, field_name)
        tool_value = getattr(tool, field_name)
        values[field_name] = (
            min(global_value, tool_value)
            if global_value is not None and tool_value is not None
            else global_value
            if tool_value is None
            else tool_value
        )
    return PolicyLimits(**values)
