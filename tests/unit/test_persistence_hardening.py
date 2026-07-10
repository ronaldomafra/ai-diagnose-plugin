from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from diagnose.audit import AuditLog
from diagnose.domain import (
    ActionReceipt,
    ActionResult,
    ActionState,
    DiagnosisSession,
    ExecutionPlan,
    FakeOperation,
    RiskClass,
    canonical_sha256,
)
from diagnose.persistence import Database, StartActionOutcome


@pytest.mark.asyncio
async def test_session_metadata_and_audit_are_atomic_and_close_is_idempotent(
    tmp_path: Path,
) -> None:
    secret = "session-secret"
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        session = await database.create_session(
            DiagnosisSession.create(metadata={"password": secret, "mode": "connected"}),
            audit_event_type="session.created",
            audit_data={"mode": "connected"},
        )
        first_close = await database.close_session(
            session.session_id,
            audit_event_type="session.closed",
            audit_data={"outcome": "CLOSED"},
        )
        second_close = await database.close_session(
            session.session_id,
            audit_event_type="session.closed",
            audit_data={"outcome": "CLOSED"},
        )

        assert session.metadata["password"] == "[REDACTED]"
        assert session.metadata["mode"] == "connected"
        assert session.metadata["_redactions"] == ["password"]
        assert first_close == second_close
        entries = await database.list_audit_entries()
        assert [entry.event_type for entry in entries] == ["session.created", "session.closed"]
        assert secret not in "".join(entry.model_dump_json() for entry in entries)


@pytest.mark.asyncio
async def test_invalid_session_audit_rolls_back_session_creation(tmp_path: Path) -> None:
    session = DiagnosisSession.create()
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        with pytest.raises(ValueError, match="invalid audit event type"):
            await database.create_session(session, audit_event_type="INVALID EVENT")

        assert await database.get_session(session.session_id) is None


async def _pending_with_plan(
    database: Database,
    *,
    request_id: str,
    secret: str | None = None,
) -> tuple[ActionReceipt, ExecutionPlan]:
    session = DiagnosisSession.create(session_id=f"DIAG-{request_id}")
    await database.create_session(session)
    summary = f"Inspect password={secret}" if secret else "Inspect test target"
    receipt = ActionReceipt.pending(
        request_id=request_id,
        session_id=session.session_id,
        target_id="fake-target",
        tool="fake_probe",
        risk=RiskClass.READ,
        summary=summary,
        now=datetime(2026, 7, 10, 12, 0, tzinfo=UTC),
    )
    plan = ExecutionPlan(
        request_id=receipt.request_id,
        session_id=receipt.session_id,
        target_id=receipt.target_id or "fake-target",
        tool=receipt.tool,
        risk=receipt.risk,
        reason=summary,
        executor="fake",
        operation=FakeOperation(output={"password": secret} if secret else {"ok": True}),
        policy_version="sha256:" + "1" * 64,
        target_version="sha256:" + "2" * 64,
    ).with_calculated_hash()
    await database.create_action(
        receipt,
        client_request_id=f"client-{request_id}",
        payload_hash=canonical_sha256({"requestId": request_id}),
        plan=plan,
    )
    persisted = await database.load_execution_plan(request_id)
    assert persisted is not None
    return receipt, persisted


async def _start(database: Database, request_id: str) -> tuple[ActionReceipt, ExecutionPlan]:
    receipt, plan = await _pending_with_plan(database, request_id=request_id)
    assert plan.action_hash is not None
    started = await database.approve_and_start_action(
        request_id,
        plan.action_hash,
        at=receipt.created_at + timedelta(seconds=1),
    )
    assert started.outcome is StartActionOutcome.STARTED
    return receipt, plan


@pytest.mark.asyncio
async def test_create_action_atomically_anchors_received_and_retry_does_not_duplicate(
    tmp_path: Path,
) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        receipt, _ = await _pending_with_plan(database, request_id="REQ-received")
        retried, created = await database.create_action(
            receipt.model_copy(update={"request_id": "REQ-unused-retry"}),
            client_request_id="client-REQ-received",
            payload_hash=canonical_sha256({"requestId": "REQ-received"}),
        )

        assert created is False
        assert retried.request_id == receipt.request_id
        received = [
            entry
            for entry in await database.list_audit_entries()
            if entry.event_type == "action.received"
        ]
        assert len(received) == 1
        assert received[0].data["argumentsHash"] == canonical_sha256({"requestId": "REQ-received"})


@pytest.mark.asyncio
async def test_finalize_action_is_atomic_sanitized_and_audit_anchored(tmp_path: Path) -> None:
    secret = "never-persist-this-token"
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        receipt, plan = await _start(database, "REQ-finalize")
        action = await database.get_action(receipt.request_id)
        assert action is not None and action.started_at is not None
        result = ActionResult(
            request_id=receipt.request_id,
            status=ActionState.COMPLETED,
            tool=receipt.tool,
            target_id=receipt.target_id,
            started_at=action.started_at,
            finished_at=action.started_at + timedelta(milliseconds=12),
            duration_ms=12,
            data={"authorization": f"Bearer {secret}", "ok": True},
            warnings=[f"token={secret}\x1b[31m"],
            redactions=["authorization", f"token={secret}", "evil@example.test"],
            truncated=True,
        )

        finalized = await database.finalize_action(
            result,
            audit_data={"actionHash": plan.action_hash, "note": f"password={secret}"},
        )

        assert finalized.action.status is ActionState.COMPLETED
        assert finalized.result_hash == finalized.audit_entry.data["resultHash"]
        assert finalized.audit_entry.data["durationMs"] == 12
        assert finalized.audit_entry.data["truncated"] is True
        assert finalized.result.data == {"authorization": "[REDACTED]", "ok": True}
        serialized = finalized.result.model_dump_json() + finalized.audit_entry.model_dump_json()
        assert secret not in serialized
        assert "\x1b" not in serialized
        assert finalized.result.redactions == ["authorization", "credential"]
        assert await database.get_result(receipt.request_id) == finalized.result


@pytest.mark.asyncio
async def test_finalize_rolls_back_result_state_event_and_audit_together(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        receipt, _ = await _start(database, "REQ-rollback")
        executing = await database.get_action(receipt.request_id)
        assert executing is not None and executing.started_at is not None
        events_before = await database.action_events(receipt.request_id)
        audits_before = await database.list_audit_entries()
        result = ActionResult(
            request_id=receipt.request_id,
            status=ActionState.COMPLETED,
            tool=receipt.tool,
            target_id=receipt.target_id,
            started_at=executing.started_at,
            finished_at=executing.started_at + timedelta(milliseconds=1),
            duration_ms=1,
        )

        with pytest.raises(ValueError, match="invalid audit event type"):
            await database.finalize_action(result, audit_event_type="INVALID EVENT")

        unchanged = await database.get_action(receipt.request_id)
        assert unchanged is not None and unchanged.status is ActionState.EXECUTING
        assert await database.get_result(receipt.request_id) is None
        assert await database.action_events(receipt.request_id) == events_before
        assert await database.list_audit_entries() == audits_before


@pytest.mark.asyncio
async def test_summary_plan_transition_detail_and_redaction_labels_are_sanitized(
    tmp_path: Path,
) -> None:
    secret = "raw-secret-material"
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        receipt, plan = await _pending_with_plan(
            database,
            request_id="REQ-sanitize",
            secret=secret,
        )
        action = await database.get_action(receipt.request_id)
        assert action is not None
        assert secret not in action.summary
        assert secret not in plan.model_dump_json()
        assert plan.verify_hash()

        await database.transition_action(
            receipt.request_id,
            ActionState.REJECTED,
            detail={"authorization": f"Bearer {secret}"},
            audit_event_type="action.rejected",
            audit_data={"reason": f"password={secret}"},
        )
        events = await database.action_events(receipt.request_id)
        audit = await database.last_audit_entry()
        assert secret not in events[-1].model_dump_json()
        assert audit is not None and secret not in audit.model_dump_json()


@pytest.mark.asyncio
async def test_restart_reconciles_approved_and_executing_without_reexecution(
    tmp_path: Path,
) -> None:
    path = tmp_path / "diagnose.sqlite3"
    database = Database(path)
    await database.initialize()
    approved_receipt, _ = await _pending_with_plan(database, request_id="REQ-approved")
    await database.transition_action(approved_receipt.request_id, ActionState.APPROVED)
    executing_receipt, _ = await _start(database, "REQ-executing")
    await database.close()

    reconciled_at = datetime(2026, 7, 10, 12, 2, tzinfo=UTC)
    async with Database(path) as restarted:
        assert await restarted.reconcile_incomplete_actions(at=reconciled_at) == 2
        for request_id in (approved_receipt.request_id, executing_receipt.request_id):
            action = await restarted.get_action(request_id)
            result = await restarted.get_result(request_id)
            assert action is not None and action.status is ActionState.FAILED
            assert result is not None and result.status is ActionState.FAILED
        reconciliation_audits = [
            entry
            for entry in await restarted.list_audit_entries()
            if entry.data.get("reason") == "crash_reconciliation"
        ]
        assert len(reconciliation_audits) == 2
        assert all(entry.data["reexecuted"] is False for entry in reconciliation_audits)


@pytest.mark.asyncio
async def test_audit_append_is_serialized_across_database_instances(tmp_path: Path) -> None:
    path = tmp_path / "diagnose.sqlite3"
    first = Database(path)
    second = Database(path)
    await first.initialize()
    await second.initialize()
    try:
        logs = (AuditLog(first), AuditLog(second))
        appends = (
            logs[index % 2].append("test.concurrent", data={"index": index}) for index in range(40)
        )
        await asyncio.gather(*appends)
        entries = await first.list_audit_entries()
        assert [entry.sequence for entry in entries] == list(range(1, 41))
        assert (await AuditLog(second).verify()).valid
    finally:
        await second.close()
        await first.close()


@pytest.mark.asyncio
async def test_expiration_race_with_approval_is_safe_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "diagnose.sqlite3"
    first = Database(path)
    second = Database(path)
    await first.initialize()
    receipt, plan = await _pending_with_plan(first, request_id="REQ-expire-race")
    await second.initialize()
    assert plan.action_hash is not None and receipt.expires_at is not None
    try:
        expired_count, approval = await asyncio.gather(
            first.expire_actions(now=receipt.expires_at),
            second.approve_and_start_action(
                receipt.request_id,
                plan.action_hash,
                at=receipt.expires_at,
            ),
        )
        assert expired_count in {0, 1}
        assert approval.outcome in {
            StartActionOutcome.EXPIRED,
            StartActionOutcome.NON_PENDING,
        }
        action = await first.get_action(receipt.request_id)
        assert action is not None and action.status is ActionState.EXPIRED
    finally:
        await second.close()
        await first.close()
