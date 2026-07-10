"""Public domain API for all Diagnose runtime components."""

from .base import DomainModel, FrozenDomainModel, to_camel
from .errors import DiagnoseError, ErrorCode, IdempotencyConflict, NormalizedError
from .hashing import canonical_bytes, canonical_json, canonical_sha256
from .models import (
    ActionReceipt,
    ActionRecord,
    ActionResult,
    CommandOperation,
    DiagnosisSession,
    ExecutionConstraints,
    ExecutionOperation,
    ExecutionPlan,
    FakeOperation,
    new_request_id,
    new_session_id,
    utc_now,
)
from .states import (
    ACTION_TRANSITIONS,
    TERMINAL_ACTION_STATES,
    ActionState,
    DiagnosisState,
    InvalidStateTransition,
    PolicyDecision,
    RiskClass,
    can_transition,
    require_transition,
)

__all__ = [
    "ACTION_TRANSITIONS",
    "TERMINAL_ACTION_STATES",
    "ActionReceipt",
    "ActionRecord",
    "ActionResult",
    "ActionState",
    "CommandOperation",
    "DiagnoseError",
    "DiagnosisSession",
    "DiagnosisState",
    "DomainModel",
    "ErrorCode",
    "ExecutionConstraints",
    "ExecutionOperation",
    "ExecutionPlan",
    "FakeOperation",
    "FrozenDomainModel",
    "IdempotencyConflict",
    "InvalidStateTransition",
    "NormalizedError",
    "PolicyDecision",
    "RiskClass",
    "can_transition",
    "canonical_bytes",
    "canonical_json",
    "canonical_sha256",
    "new_request_id",
    "new_session_id",
    "require_transition",
    "to_camel",
    "utc_now",
]
