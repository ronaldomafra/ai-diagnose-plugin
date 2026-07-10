"""State and risk enums plus the authoritative action state machine."""

from __future__ import annotations

from enum import StrEnum


class ActionState(StrEnum):
    RECEIVED = "RECEIVED"
    POLICY_REJECTED = "POLICY_REJECTED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class DiagnosisState(StrEnum):
    COLLECTING = "COLLECTING"
    INVESTIGATING = "INVESTIGATING"
    WAITING_USER = "WAITING_USER"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    BLOCKED = "BLOCKED"
    RESOLVED = "RESOLVED"
    INTERRUPTED = "INTERRUPTED"
    CLOSED = "CLOSED"


class RiskClass(StrEnum):
    LOCAL_METADATA = "LOCAL_METADATA"
    READ = "READ"
    ACTIVE_PROBE = "ACTIVE_PROBE"
    SENSITIVE_READ = "SENSITIVE_READ"
    MUTATION = "MUTATION"
    DESTRUCTIVE = "DESTRUCTIVE"


class PolicyDecision(StrEnum):
    DENY = "DENY"
    ALLOW_WITH_APPROVAL = "ALLOW_WITH_APPROVAL"
    # Reserved for protocol compatibility. The v1 policy engine never grants it.
    ALLOW_AUTOMATIC = "ALLOW_AUTOMATIC"


ACTION_TRANSITIONS: dict[ActionState, frozenset[ActionState]] = {
    ActionState.RECEIVED: frozenset({ActionState.POLICY_REJECTED, ActionState.PENDING_APPROVAL}),
    ActionState.PENDING_APPROVAL: frozenset(
        {
            ActionState.APPROVED,
            ActionState.REJECTED,
            ActionState.EXPIRED,
            ActionState.CANCELLED,
        }
    ),
    ActionState.APPROVED: frozenset({ActionState.EXECUTING}),
    ActionState.EXECUTING: frozenset(
        {ActionState.COMPLETED, ActionState.FAILED, ActionState.CANCELLED}
    ),
    ActionState.POLICY_REJECTED: frozenset(),
    ActionState.COMPLETED: frozenset(),
    ActionState.REJECTED: frozenset(),
    ActionState.EXPIRED: frozenset(),
    ActionState.FAILED: frozenset(),
    ActionState.CANCELLED: frozenset(),
}


TERMINAL_ACTION_STATES = frozenset(
    {
        ActionState.POLICY_REJECTED,
        ActionState.COMPLETED,
        ActionState.REJECTED,
        ActionState.EXPIRED,
        ActionState.FAILED,
        ActionState.CANCELLED,
    }
)


class InvalidStateTransition(ValueError):
    """Raised when persisted state would violate the documented state machine."""

    def __init__(self, current: ActionState, requested: ActionState) -> None:
        super().__init__(f"action state cannot transition from {current} to {requested}")
        self.current = current
        self.requested = requested


def can_transition(current: ActionState, requested: ActionState) -> bool:
    """Return whether an action transition is explicitly authorized."""

    return requested in ACTION_TRANSITIONS[current]


def require_transition(current: ActionState, requested: ActionState) -> None:
    """Validate an action transition, raising a typed error when it is invalid."""

    if not can_transition(current, requested):
        raise InvalidStateTransition(current, requested)
