from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from diagnose.domain import (
    ActionReceipt,
    ActionResult,
    ActionState,
    DiagnosisSession,
    ExecutionPlan,
    FakeOperation,
    IdempotencyConflict,
    InvalidStateTransition,
    RiskClass,
    canonical_sha256,
)
from diagnose.persistence import Database


def plan_for(receipt: ActionReceipt) -> ExecutionPlan:
    return ExecutionPlan(
        request_id=receipt.request_id,
        session_id=receipt.session_id,
        target_id=receipt.target_id or "test",
        tool=receipt.tool,
        risk=receipt.risk,
        reason="Exercise the approval flow",
        executor="fake",
        operation=FakeOperation(output={"ok": True}),
        policy_version="sha256:" + "1" * 64,
        target_version="sha256:" + "2" * 64,
    ).with_calculated_hash()


async def create_pending(db: Database) -> tuple[DiagnosisSession, ActionReceipt]:
    session = DiagnosisSession.create()
    await db.create_session(session)
    receipt = ActionReceipt.pending(
        session_id=session.session_id,
        target_id="test-target",
        tool="fake_test",
        risk=RiskClass.READ,
        summary="Run the fake test",
    )
    return session, receipt


@pytest.mark.asyncio
async def test_migrations_sessions_idempotency_and_plan_roundtrip(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as db:
        session, receipt = await create_pending(db)
        payload_hash = canonical_sha256({"targetId": "test-target"})

        created, is_new = await db.create_action(
            receipt,
            client_request_id="client-1",
            payload_hash=payload_hash,
            plan=plan_for(receipt),
        )
        retried, retry_is_new = await db.create_action(
            ActionReceipt.pending(
                session_id=session.session_id,
                target_id="test-target",
                tool="fake_test",
                risk=RiskClass.READ,
                summary="Would otherwise be a second action",
            ),
            client_request_id="client-1",
            payload_hash=payload_hash,
        )

        assert is_new is True
        assert retry_is_new is False
        assert retried.request_id == created.request_id
        assert (await db.load_execution_plan(receipt.request_id)) == plan_for(receipt)
        assert await db.integrity_check() == ("ok",)
        with pytest.raises(IdempotencyConflict):
            await db.create_action(
                receipt.model_copy(update={"request_id": "REQ-changed"}),
                client_request_id="client-1",
                payload_hash=canonical_sha256({"changed": True}),
            )


@pytest.mark.asyncio
async def test_state_events_result_and_invalid_transition(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as db:
        _, receipt = await create_pending(db)
        await db.create_action(
            receipt,
            client_request_id="client-1",
            payload_hash=canonical_sha256({"request": 1}),
        )
        await db.transition_action(receipt.request_id, ActionState.APPROVED)
        executing = await db.transition_action(receipt.request_id, ActionState.EXECUTING)
        completed = await db.transition_action(receipt.request_id, ActionState.COMPLETED)
        assert executing.started_at is not None
        assert completed.finished_at is not None

        result = ActionResult(
            request_id=receipt.request_id,
            status=ActionState.COMPLETED,
            tool=receipt.tool,
            target_id=receipt.target_id,
            started_at=executing.started_at,
            finished_at=completed.finished_at,
            duration_ms=1,
            data={"safe": "evidence"},
        )
        result_hash = await db.store_result(result)

        assert result_hash.startswith("sha256:")
        assert await db.get_result(receipt.request_id) == result
        assert len(await db.action_events(receipt.request_id)) == 4
        with pytest.raises(InvalidStateTransition):
            await db.transition_action(receipt.request_id, ActionState.EXECUTING)


@pytest.mark.asyncio
async def test_restart_reconciles_executing_action_to_failed(tmp_path: Path) -> None:
    path = tmp_path / "diagnose.sqlite3"
    db = Database(path)
    await db.initialize()
    _, receipt = await create_pending(db)
    await db.create_action(
        receipt,
        client_request_id="client-1",
        payload_hash=canonical_sha256({"request": 1}),
    )
    await db.transition_action(receipt.request_id, ActionState.APPROVED)
    await db.transition_action(receipt.request_id, ActionState.EXECUTING)
    await db.close()

    async with Database(path) as restarted:
        assert await restarted.reconcile_incomplete_actions() == 1
        action = await restarted.get_action(receipt.request_id)
        assert action is not None
        assert action.status is ActionState.FAILED
        assert action.error is not None


@pytest.mark.asyncio
async def test_pending_actions_expire_at_deadline(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as db:
        session = DiagnosisSession.create()
        await db.create_session(session)
        receipt = ActionReceipt.pending(
            session_id=session.session_id,
            target_id="test-target",
            tool="fake_test",
            risk=RiskClass.READ,
            summary="Run the fake test",
            now=datetime(2026, 7, 10, 12, 0, tzinfo=UTC),
        )
        await db.create_action(
            receipt,
            client_request_id="client-1",
            payload_hash=canonical_sha256({"request": 1}),
        )

        count = await db.expire_actions(now=datetime(2026, 7, 10, 12, 6, tzinfo=UTC))

        assert count == 1
        action = await db.get_action(receipt.request_id)
        assert action is not None and action.status is ActionState.EXPIRED


@pytest.mark.asyncio
async def test_persistence_sanitizes_result_as_defense_in_depth(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as db:
        _, receipt = await create_pending(db)
        await db.create_action(
            receipt,
            client_request_id="client-1",
            payload_hash=canonical_sha256({"request": 1}),
        )
        result = ActionResult(
            request_id=receipt.request_id,
            status=ActionState.COMPLETED,
            tool=receipt.tool,
            target_id=receipt.target_id,
            finished_at=datetime.now(UTC),
            duration_ms=1,
            data={"authorization": "Bearer raw-secret"},
        )

        await db.store_result(result)
        persisted = await db.get_result(receipt.request_id)

        assert persisted is not None
        assert persisted.data == {"authorization": "[REDACTED]"}
        assert "authorization" in persisted.redactions
