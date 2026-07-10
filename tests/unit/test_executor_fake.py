from __future__ import annotations

import asyncio

import pytest

from diagnose.domain import (
    ExecutionConstraints,
    ExecutionPlan,
    FakeOperation,
    RiskClass,
    canonical_sha256,
)
from diagnose.executors.fake import FakeExecutionError, FakeExecutor


def _plan() -> ExecutionPlan:
    return ExecutionPlan(
        request_id="REQ-test",
        session_id="DIAG-test",
        target_id="fake-target",
        tool="fake_probe",
        risk=RiskClass.READ,
        reason="Exercise the test executor",
        executor="fake",
        operation=FakeOperation(output={"ok": True}),
        constraints=ExecutionConstraints(),
        policy_version=canonical_sha256({"policy": "test"}),
        target_version=canonical_sha256({"target": "test"}),
    ).with_calculated_hash()


@pytest.mark.asyncio
async def test_fake_executor_returns_configured_data() -> None:
    executor = FakeExecutor({"value": 42})

    result = await executor.execute(_plan(), asyncio.Event())

    assert result.data == {"value": 42}
    assert executor.calls == 1


@pytest.mark.asyncio
async def test_fake_executor_honors_cancellation() -> None:
    executor = FakeExecutor(delay_seconds=10)
    cancel_event = asyncio.Event()
    cancel_event.set()

    with pytest.raises(asyncio.CancelledError):
        await executor.execute(_plan(), cancel_event)


@pytest.mark.asyncio
async def test_fake_executor_can_fail_deterministically() -> None:
    executor = FakeExecutor(error="expected failure")

    with pytest.raises(FakeExecutionError, match="expected failure"):
        await executor.execute(_plan(), asyncio.Event())
