from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from diagnose.domain import (
    ActionReceipt,
    ActionState,
    ExecutionPlan,
    FakeOperation,
    RiskClass,
    canonical_json,
    canonical_sha256,
)


def make_plan(**changes: object) -> ExecutionPlan:
    values: dict[str, object] = {
        "request_id": "REQ-test",
        "session_id": "DIAG-test",
        "target_id": "production-api",
        "tool": "service_logs",
        "risk": RiskClass.SENSITIVE_READ,
        "reason": "Confirm the failure",
        "executor": "fake",
        "operation": FakeOperation(output={"status": "ok"}),
        "policy_version": "sha256:" + "1" * 64,
        "target_version": "sha256:" + "2" * 64,
    }
    values.update(changes)
    return ExecutionPlan(**values)  # type: ignore[arg-type]


def test_models_serialize_camel_case_and_reject_unknown_fields() -> None:
    plan = make_plan().with_calculated_hash()

    wire = plan.model_dump(mode="json", by_alias=True)

    assert wire["requestId"] == "REQ-test"
    assert wire["policyVersion"].startswith("sha256:")
    with pytest.raises(ValidationError):
        ExecutionPlan.model_validate({**wire, "agentRiskOverride": "READ"})


def test_plan_hash_is_deterministic_and_commits_policy_and_target_versions() -> None:
    first = make_plan().with_calculated_hash()
    reordered_output = FakeOperation(output={"b": 2, "a": 1})
    same_output = FakeOperation(output={"a": 1, "b": 2})
    left = make_plan(operation=reordered_output).with_calculated_hash()
    right = make_plan(operation=same_output).with_calculated_hash()

    assert first.verify_hash()
    assert left.action_hash == right.action_hash
    assert make_plan(policy_version="sha256:" + "3" * 64).calculate_hash() != first.action_hash
    assert make_plan(target_version="sha256:" + "4" * 64).calculate_hash() != first.action_hash
    assert first.model_copy(update={"reason": "tampered"}).verify_hash() is False


def test_canonical_json_is_utf8_stable_and_rejects_non_finite_numbers() -> None:
    assert canonical_json({"z": "ação", "a": 1}) == '{"a":1,"z":"ação"}'
    assert canonical_sha256({"b": 2, "a": 1}) == canonical_sha256({"a": 1, "b": 2})
    with pytest.raises(ValueError):
        canonical_json({"bad": float("nan")})


def test_pending_receipt_has_five_minute_default_expiration() -> None:
    now = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)
    receipt = ActionReceipt.pending(
        session_id="DIAG-test",
        target_id="local",
        tool="fake_test",
        risk=RiskClass.READ,
        summary="Read safe metadata",
        now=now,
    )

    assert receipt.status is ActionState.PENDING_APPROVAL
    assert receipt.expires_at is not None
    assert (receipt.expires_at - receipt.created_at).total_seconds() == 300
