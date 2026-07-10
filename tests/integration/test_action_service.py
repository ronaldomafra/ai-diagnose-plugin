from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from diagnose.approval import ActionService, ActionSubmission
from diagnose.config import Configuration, Settings, TargetConfig, TargetSet
from diagnose.domain import (
    ActionState,
    DiagnoseError,
    ErrorCode,
    FakeOperation,
    IdempotencyConflict,
    PolicyDecision,
)
from diagnose.executors.fake import FakeExecutor
from diagnose.persistence import Database
from diagnose.policy import PolicyDefinition, PolicySet, ToolPolicy


def _configuration(tmp_path: Path, *, allowed: bool = True) -> Configuration:
    decision = PolicyDecision.ALLOW_WITH_APPROVAL if allowed else PolicyDecision.DENY
    return Configuration(
        config_dir=tmp_path,
        settings=Settings(approval_timeout_seconds=30),
        target_set=TargetSet(
            targets=[
                TargetConfig(
                    id="fake-target",
                    display_name="Fake target",
                    type="fake",
                    connection_ref="fake:target",
                    policy_ref="fake-policy",
                    capabilities=["fake_probe"],
                )
            ]
        ),
        policy_set=PolicySet(
            policies={
                "fake-policy": PolicyDefinition(
                    targets=["fake-target"],
                    tools={
                        "fake_probe": ToolPolicy(
                            decision=decision,
                            timeout_seconds=5,
                            max_output_bytes=4096,
                        )
                    },
                )
            }
        ),
    )


@asynccontextmanager
async def _service(
    tmp_path: Path,
    configuration_provider: object | None = None,
    *,
    executor: FakeExecutor | None = None,
) -> AsyncIterator[tuple[ActionService, Database]]:
    database = Database(tmp_path / "diagnose.sqlite3")
    await database.initialize()
    configuration = _configuration(tmp_path)
    provider = configuration_provider or (lambda: configuration)
    service = ActionService(
        database,
        provider,  # type: ignore[arg-type]
        executors={"fake": executor or FakeExecutor({"password": "secret", "log": "\x1b[31mred"})},
    )
    try:
        yield service, database
    finally:
        await service.close()
        await database.close()


async def _create_session(database: Database) -> str:
    from diagnose.domain import DiagnosisSession

    session = await database.create_session(DiagnosisSession.create())
    return session.session_id


def _submission(session_id: str, *, client_id: str = "client-1") -> ActionSubmission:
    return ActionSubmission(
        session_id=session_id,
        target_id="fake-target",
        tool="fake_probe",
        reason="Exercise the approval pipeline",
        client_request_id=client_id,
        operation=FakeOperation(output={"ok": True}),
    )


async def _wait_for_terminal(service: ActionService, request_id: str) -> ActionState:
    for _ in range(100):
        state = (await service.status(request_id)).status
        if state in {ActionState.COMPLETED, ActionState.FAILED, ActionState.CANCELLED}:
            return state
        await asyncio.sleep(0.01)
    raise AssertionError("action did not reach a terminal state")


@pytest.mark.asyncio
async def test_action_executes_only_after_exact_plan_is_approved(tmp_path: Path) -> None:
    executor = FakeExecutor({"password": "secret", "log": "\x1b[31mred"})
    async with _service(tmp_path, executor=executor) as (service, database):
        session_id = await _create_session(database)

        pending = await service.submit(_submission(session_id))

        assert pending.status is ActionState.PENDING_APPROVAL
        assert executor.calls == 0
        plan = await database.load_execution_plan(pending.request_id)
        assert plan is not None and plan.verify_hash()

        approved = await service.approve(pending.request_id)
        assert approved.status is ActionState.EXECUTING
        assert await _wait_for_terminal(service, pending.request_id) is ActionState.COMPLETED

        result = await service.result(pending.request_id)
        assert result is not None
        assert result.data == {"password": "[REDACTED]", "log": "red"}
        assert "password" in result.redactions
        assert executor.calls == 1
        assert (await service.audit.verify()).valid is True


@pytest.mark.asyncio
async def test_idempotent_retry_reuses_action_and_changed_payload_fails(tmp_path: Path) -> None:
    async with _service(tmp_path) as (service, database):
        session_id = await _create_session(database)
        first = await service.submit(_submission(session_id))
        retry = await service.submit(_submission(session_id))

        assert retry.request_id == first.request_id

        changed = _submission(session_id).model_copy(update={"reason": "Changed reason"})
        with pytest.raises(IdempotencyConflict):
            await service.submit(changed)


@pytest.mark.asyncio
async def test_policy_change_expires_pending_approval(tmp_path: Path) -> None:
    current = _configuration(tmp_path)

    def provider() -> Configuration:
        return current

    async with _service(tmp_path, provider) as (service, database):
        session_id = await _create_session(database)
        pending = await service.submit(_submission(session_id))
        current = _configuration(tmp_path, allowed=False)

        with pytest.raises(DiagnoseError) as captured:
            await service.approve(pending.request_id)

        assert captured.value.error.code is ErrorCode.APPROVAL_EXPIRED
        assert (await service.status(pending.request_id)).status is ActionState.EXPIRED


@pytest.mark.asyncio
async def test_rejection_never_calls_executor(tmp_path: Path) -> None:
    executor = FakeExecutor()
    async with _service(tmp_path, executor=executor) as (service, database):
        session_id = await _create_session(database)
        pending = await service.submit(_submission(session_id))

        rejected = await service.reject(pending.request_id, "Not needed")

        assert rejected.status is ActionState.REJECTED
        assert executor.calls == 0
        assert await database.get_result(pending.request_id) is None
        audit_entries = await database.list_audit_entries()
        assert sum(entry.event_type == "action.rejected" for entry in audit_entries) == 1
