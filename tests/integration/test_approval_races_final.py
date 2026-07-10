from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import pytest

from diagnose.approval import ActionService, ActionSubmission
from diagnose.config import Configuration, Settings, TargetConfig, TargetSet
from diagnose.domain import (
    ActionState,
    DiagnoseError,
    DiagnosisSession,
    ErrorCode,
    ExecutionPlan,
    FakeOperation,
    PolicyDecision,
)
from diagnose.executors.fake import FakeExecutor
from diagnose.persistence import Database, StartActionOutcome, StartActionResult
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


class PostCommitPauseDatabase(Database):
    """Expose the yield immediately after the start transaction committed."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.start_committed = asyncio.Event()
        self.release_start_result = asyncio.Event()

    async def approve_and_start_action(
        self,
        request_id: str,
        expected_action_hash: str,
        *,
        at: datetime | None = None,
        approver: str | None = None,
        precondition: Callable[[ExecutionPlan], bool] | None = None,
    ) -> StartActionResult:
        result = await super().approve_and_start_action(
            request_id,
            expected_action_hash,
            at=at,
            approver=approver,
            precondition=precondition,
        )
        if result.outcome is StartActionOutcome.STARTED:
            self.start_committed.set()
            await self.release_start_result.wait()
        return result


@asynccontextmanager
async def _service(
    tmp_path: Path,
    *,
    database: Database | None = None,
    configuration_provider: Callable[[], Configuration] | None = None,
    executor: FakeExecutor | None = None,
) -> AsyncIterator[tuple[ActionService, Database, FakeExecutor]]:
    db = database or Database(tmp_path / "diagnose.sqlite3")
    await db.initialize()
    configuration = _configuration(tmp_path)
    fake = executor or FakeExecutor()
    service = ActionService(
        db,
        configuration_provider or (lambda: configuration),
        executors={"fake": fake},
    )
    try:
        yield service, db, fake
    finally:
        await service.close()
        await db.close()


async def _submit(
    service: ActionService,
    database: Database,
    *,
    client_request_id: str = "opaque-client-key",
) -> str:
    session = await database.create_session(DiagnosisSession.create())
    action = await service.submit(
        ActionSubmission(
            session_id=session.session_id,
            target_id="fake-target",
            tool="fake_probe",
            reason="Exercise approval race handling",
            client_request_id=client_request_id,
            operation=FakeOperation(output={"ok": True}),
        )
    )
    assert action.status is ActionState.PENDING_APPROVAL
    return action.request_id


@pytest.mark.asyncio
async def test_cancelling_approve_after_start_commit_waits_for_runner_registration(
    tmp_path: Path,
) -> None:
    database = PostCommitPauseDatabase(tmp_path / "diagnose.sqlite3")
    executor = FakeExecutor(delay_seconds=5)
    async with _service(
        tmp_path,
        database=database,
        executor=executor,
    ) as (service, _, _):
        request_id = await _submit(service, database)
        approval = asyncio.create_task(service.approve(request_id))

        await asyncio.wait_for(database.start_committed.wait(), timeout=2)
        committed = await database.get_action(request_id)
        assert committed is not None and committed.status is ActionState.EXECUTING

        approval.cancel()
        await asyncio.sleep(0)
        assert not approval.done()

        database.release_start_result.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(approval, timeout=2)

        assert service.queue.empty()
        for _ in range(100):
            if executor.calls:
                break
            await asyncio.sleep(0.01)
        assert executor.calls == 1
        cancelled = await service.cancel(request_id, "test cleanup")
        assert cancelled.status is ActionState.CANCELLED


@pytest.mark.asyncio
async def test_configuration_is_revalidated_inside_atomic_start(tmp_path: Path) -> None:
    original = _configuration(tmp_path)
    denied = _configuration(tmp_path, allowed=False)
    calls = 0

    def provider() -> Configuration:
        nonlocal calls
        calls += 1
        # submit and the preliminary plan read see the original configuration;
        # only the transaction-scoped precondition sees the change.
        return original if calls <= 2 else denied

    async with _service(
        tmp_path,
        configuration_provider=provider,
    ) as (service, database, executor):
        request_id = await _submit(service, database)

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
async def test_client_request_id_is_not_part_of_payload_hash(tmp_path: Path) -> None:
    async with _service(tmp_path) as (service, database, _):
        session = await database.create_session(DiagnosisSession.create())

        def submission(client_request_id: str) -> ActionSubmission:
            return ActionSubmission(
                session_id=session.session_id,
                target_id="fake-target",
                tool="fake_probe",
                reason="Same operation",
                client_request_id=client_request_id,
                operation=FakeOperation(output={"ok": True}),
            )

        first = await service.submit(submission("opaque-key-one"))
        second = await service.submit(submission("opaque-key-two"))
        assert first.request_id != second.request_id

        connection = database._require_connection()
        rows = list(
            await (
                await connection.execute(
                    "SELECT payload_hash FROM idempotency_keys ORDER BY rowid",
                )
            ).fetchall()
        )
        assert len(rows) == 2
        assert rows[0]["payload_hash"] == rows[1]["payload_hash"]
