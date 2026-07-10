from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from anyio import to_thread

import diagnose.approval.service as action_service_module
from diagnose.approval import ActionService, ActionSubmission
from diagnose.config import Configuration, Settings, TargetConfig, TargetSet
from diagnose.domain import (
    ActionState,
    DiagnoseError,
    DiagnosisSession,
    ErrorCode,
    FakeOperation,
    PolicyDecision,
)
from diagnose.executors.fake import FakeExecutor
from diagnose.persistence import Database
from diagnose.policy import PolicyDefinition, PolicySet, ToolPolicy


def _configuration(tmp_path: Path) -> Configuration:
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
                            decision=PolicyDecision.ALLOW_WITH_APPROVAL,
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
    *,
    executor: FakeExecutor | None = None,
    configuration_provider: Callable[[], Configuration] | None = None,
) -> AsyncIterator[tuple[ActionService, Database, FakeExecutor]]:
    database = Database(tmp_path / "diagnose.sqlite3")
    await database.initialize()
    configuration = _configuration(tmp_path)
    fake = executor or FakeExecutor()
    service = ActionService(
        database,
        configuration_provider or (lambda: configuration),
        executors={"fake": fake},
    )
    try:
        yield service, database, fake
    finally:
        await service.close()
        await database.close()


async def _pending(
    service: ActionService,
    database: Database,
    *,
    reason: str = "Exercise the approval pipeline",
    operation: FakeOperation | None = None,
) -> tuple[str, str]:
    session = await database.create_session(DiagnosisSession.create())
    action = await service.submit(
        ActionSubmission(
            session_id=session.session_id,
            target_id="fake-target",
            tool="fake_probe",
            reason=reason,
            client_request_id=f"client-{session.session_id}",
            operation=operation or FakeOperation(),
        )
    )
    assert action.status is ActionState.PENDING_APPROVAL
    return session.session_id, action.request_id


async def _wait_for_executor(executor: FakeExecutor) -> None:
    for _ in range(100):
        if executor.calls:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("executor did not start")


async def _wait_for_terminal(database: Database, request_id: str) -> ActionState:
    for _ in range(100):
        action = await database.get_action(request_id)
        assert action is not None
        if action.status in {ActionState.COMPLETED, ActionState.FAILED, ActionState.CANCELLED}:
            return action.status
        await asyncio.sleep(0.01)
    raise AssertionError("action did not finish")


def _persisted_database_bytes(directory: Path) -> bytes:
    return b"".join(path.read_bytes() for path in directory.glob("diagnose.sqlite3*"))


@pytest.mark.asyncio
async def test_approval_at_exact_deadline_expires_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with _service(tmp_path) as (service, database, executor):
        _, request_id = await _pending(service, database)
        pending = await database.get_action(request_id)
        assert pending is not None and pending.expires_at is not None
        monkeypatch.setattr(action_service_module, "utc_now", lambda: pending.expires_at)

        with pytest.raises(DiagnoseError) as captured:
            await service.approve(request_id)

        assert captured.value.error.code is ErrorCode.APPROVAL_EXPIRED
        action = await database.get_action(request_id)
        assert action is not None and action.status is ActionState.EXPIRED
        assert executor.calls == 0
        assert [event.to_state for event in await database.action_events(request_id)] == [
            ActionState.RECEIVED.value,
            ActionState.PENDING_APPROVAL.value,
            ActionState.EXPIRED.value,
        ]


@pytest.mark.asyncio
async def test_approval_rejects_a_session_closed_after_submission(tmp_path: Path) -> None:
    async with _service(tmp_path) as (service, database, executor):
        session_id, request_id = await _pending(service, database)
        await database.close_session(session_id)

        with pytest.raises(DiagnoseError):
            await service.approve(request_id)

        action = await database.get_action(request_id)
        assert action is not None and action.status is ActionState.CANCELLED
        assert await database.get_result(request_id) is not None
        assert executor.calls == 0


@pytest.mark.asyncio
async def test_close_during_approval_never_leaves_approved_action(tmp_path: Path) -> None:
    executor = FakeExecutor(delay_seconds=5)
    async with _service(tmp_path, executor=executor) as (service, database, _):
        _, request_id = await _pending(service, database)
        await service.approve(request_id)
        await _wait_for_executor(executor)

        await service.close()

        action = await database.get_action(request_id)
        assert action is not None
        assert action.status is ActionState.CANCELLED
        assert action.status is not ActionState.APPROVED


@pytest.mark.asyncio
async def test_tampered_plan_cannot_be_approved(tmp_path: Path) -> None:
    async with _service(tmp_path) as (service, database, executor):
        _, request_id = await _pending(service, database)
        connection = database._require_connection()
        row = await (
            await connection.execute(
                "SELECT plan_json FROM execution_plans WHERE request_id = ?",
                (request_id,),
            )
        ).fetchone()
        assert row is not None
        payload = json.loads(row["plan_json"])
        payload["reason"] = "tampered after review"
        await connection.execute("DROP TRIGGER execution_plans_no_update")
        await connection.execute(
            "UPDATE execution_plans SET plan_json = ? WHERE request_id = ?",
            (json.dumps(payload), request_id),
        )
        await connection.commit()

        with pytest.raises(DiagnoseError) as captured:
            await service.approve(request_id)

        assert captured.value.error.code is ErrorCode.APPROVAL_EXPIRED
        action = await database.get_action(request_id)
        assert action is not None and action.status is ActionState.EXPIRED
        assert executor.calls == 0


@pytest.mark.asyncio
async def test_secrets_are_removed_before_plan_hash_persistence_and_render(
    tmp_path: Path,
) -> None:
    async with _service(tmp_path) as (service, database, _):
        secret = "hunter2-never-store"
        reason = f"Investigate password={secret}\x1b[31m"
        operation = FakeOperation(
            output={
                "password": secret,
                "note": f"token={secret}",
                "terminal": "\x1b]0;unsafe\x07visible",
            }
        )
        _, request_id = await _pending(
            service,
            database,
            reason=reason,
            operation=operation,
        )

        plan = await database.load_execution_plan(request_id)
        assert plan is not None and plan.verify_hash()
        rendered = await service.render_plan(request_id)
        persisted_bytes = await to_thread.run_sync(_persisted_database_bytes, tmp_path)

        assert secret not in plan.model_dump_json()
        assert secret not in rendered
        assert secret.encode() not in persisted_bytes
        assert "[REDACTED]" in rendered
        assert "\x1b" not in rendered


@pytest.mark.asyncio
async def test_concurrent_execution_cancellation_has_one_transition_and_audit(
    tmp_path: Path,
) -> None:
    executor = FakeExecutor(delay_seconds=5)
    async with _service(tmp_path, executor=executor) as (service, database, _):
        _, request_id = await _pending(service, database)
        await service.approve(request_id)
        await _wait_for_executor(executor)

        first, second = await asyncio.gather(
            service.cancel(request_id, "user request"),
            service.cancel(request_id, "duplicate request"),
        )

        assert first.status is ActionState.CANCELLED
        assert second.status is ActionState.CANCELLED
        events = await database.action_events(request_id)
        assert sum(event.to_state == ActionState.CANCELLED.value for event in events) == 1
        audit_entries = await database.list_audit_entries()
        assert sum(entry.event_type == "action.cancelled" for entry in audit_entries) == 1


@pytest.mark.asyncio
async def test_atomic_start_and_finalize_have_one_complete_audit_chain(tmp_path: Path) -> None:
    async with _service(tmp_path) as (service, database, executor):
        _, request_id = await _pending(service, database)

        started = await service.approve(request_id)

        assert started.status is ActionState.EXECUTING
        assert await _wait_for_terminal(database, request_id) is ActionState.COMPLETED
        assert executor.calls == 1
        events = await database.action_events(request_id)
        assert [event.to_state for event in events] == [
            ActionState.RECEIVED.value,
            ActionState.PENDING_APPROVAL.value,
            ActionState.APPROVED.value,
            ActionState.EXECUTING.value,
            ActionState.COMPLETED.value,
        ]
        audit_entries = await database.list_audit_entries()
        approved = [entry for entry in audit_entries if entry.event_type == "action.approved"]
        completed = [entry for entry in audit_entries if entry.event_type == "action.completed"]
        assert len(approved) == len(completed) == 1
        assert approved[0].data["approver"]
        assert str(completed[0].data["resultHash"]).startswith("sha256:")
        assert completed[0].data["status"] == ActionState.COMPLETED.value
        assert "durationMs" in completed[0].data
        assert (await service.audit.verify()).valid is True


@pytest.mark.asyncio
async def test_pending_cancel_is_idempotent_audited_and_has_no_execution_result(
    tmp_path: Path,
) -> None:
    async with _service(tmp_path) as (service, database, executor):
        _, request_id = await _pending(service, database)

        first, second = await asyncio.gather(
            service.cancel(request_id, "user request"),
            service.cancel(request_id, "duplicate request"),
        )

        assert first.status is second.status is ActionState.CANCELLED
        assert executor.calls == 0
        assert await database.get_result(request_id) is None
        audit_entries = await database.list_audit_entries()
        assert sum(entry.event_type == "action.cancelled" for entry in audit_entries) == 1


@pytest.mark.asyncio
async def test_target_change_expires_reviewed_plan_without_calling_executor(tmp_path: Path) -> None:
    current = _configuration(tmp_path)

    def provider() -> Configuration:
        return current

    async with _service(
        tmp_path,
        configuration_provider=provider,
    ) as (service, database, executor):
        _, request_id = await _pending(service, database)
        changed_target = current.targets[0].model_copy(update={"display_name": "Renamed target"})
        current = current.model_copy(update={"target_set": TargetSet(targets=[changed_target])})

        with pytest.raises(DiagnoseError) as captured:
            await service.approve(request_id)

        assert captured.value.error.code is ErrorCode.APPROVAL_EXPIRED
        action = await database.get_action(request_id)
        assert action is not None and action.status is ActionState.EXPIRED
        assert executor.calls == 0
        audit_entries = await database.list_audit_entries()
        assert sum(entry.event_type == "action.expired" for entry in audit_entries) == 1
