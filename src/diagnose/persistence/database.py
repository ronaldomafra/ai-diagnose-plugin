"""Async SQLite persistence with migrations and state-machine enforcement."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any, cast

import aiosqlite
from pydantic import JsonValue

from diagnose.domain import (
    TERMINAL_ACTION_STATES,
    ActionReceipt,
    ActionRecord,
    ActionResult,
    ActionState,
    DiagnosisSession,
    DiagnosisState,
    ErrorCode,
    ExecutionPlan,
    IdempotencyConflict,
    NormalizedError,
    canonical_json,
    canonical_sha256,
    require_transition,
    utc_now,
)
from diagnose.sanitization import Sanitizer

from .records import (
    AUDIT_GENESIS_HASH,
    ActionEvent,
    FinalizedAction,
    KnownHostFingerprint,
    StartActionOutcome,
    StartActionResult,
    StoredAuditEntry,
)

_AUDIT_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,199}$")
_TRUSTED_REDACTION_LABELS = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "awssecretaccesskey",
        "clientsecret",
        "connectionstring",
        "cookie",
        "credential",
        "custom-pattern",
        "databaseurl",
        "dbpassword",
        "jwt",
        "password",
        "passwd",
        "private-key",
        "privatekey",
        "proxyauthorization",
        "pwd",
        "refreshtoken",
        "secret",
        "secretkey",
        "sensitive-field",
        "setcookie",
        "token",
        "uri-userinfo",
    }
)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _required_timestamp(value: str) -> datetime:
    timestamp = _parse_timestamp(value)
    assert timestamp is not None
    return timestamp


def _decode_json(value: str | None) -> Any:
    return json.loads(value) if value is not None else None


class DatabaseNotInitialized(RuntimeError):
    pass


class Database:
    """Single-process asynchronous repository for the Terminal Server.

    Calls are serialized on one SQLite connection. This keeps action creation,
    idempotency registration, and state events atomic while WAL still permits
    external read-only inspection.
    """

    def __init__(self, path: str | Path, *, sanitizer: Sanitizer | None = None) -> None:
        self.path = Path(path).expanduser().resolve()
        self.sanitizer = sanitizer or Sanitizer()
        self._connection: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> Database:
        await self.initialize()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def initialize(self) -> None:
        if self._connection is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.path.parent.chmod(0o700)
        connection = await aiosqlite.connect(self.path)
        connection.row_factory = aiosqlite.Row
        try:
            await connection.execute("PRAGMA foreign_keys = ON")
            await connection.execute("PRAGMA journal_mode = WAL")
            await connection.execute("PRAGMA synchronous = FULL")
            await connection.execute("PRAGMA busy_timeout = 5000")
            self._connection = connection
            await self._apply_migrations()
            await self._hash_legacy_idempotency_keys()
            if os.name != "nt":
                self.path.chmod(0o600)
        except BaseException:
            self._connection = None
            await connection.close()
            raise

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None

    def _require_connection(self) -> aiosqlite.Connection:
        if self._connection is None:
            raise DatabaseNotInitialized("call initialize() before using the database")
        return self._connection

    async def _apply_migrations(self) -> None:
        connection = self._require_connection()
        await connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        rows = await (await connection.execute("SELECT version FROM schema_migrations")).fetchall()
        applied = {int(row["version"]) for row in rows}
        migration_root = resources.files("diagnose.persistence.migrations")
        migration_files = sorted(
            (item for item in migration_root.iterdir() if item.name.endswith(".sql")),
            key=lambda item: item.name,
        )
        for migration in migration_files:
            prefix = migration.name.split("_", 1)[0]
            if not prefix.isdigit():
                raise RuntimeError(f"invalid migration filename: {migration.name}")
            version = int(prefix)
            if version in applied:
                continue
            script = migration.read_text(encoding="utf-8")
            name = migration.name.replace("'", "''")
            applied_at = _timestamp(utc_now())
            transactional_script = (
                "BEGIN IMMEDIATE;\n"
                f"{script}\n"
                "INSERT INTO schema_migrations(version, name, applied_at) "
                f"VALUES ({version}, '{name}', '{applied_at}');\n"
                "COMMIT;"
            )
            try:
                await connection.executescript(transactional_script)
            except BaseException:
                await connection.rollback()
                raise

    async def _hash_legacy_idempotency_keys(self) -> None:
        """One-time upgrade of legacy plaintext idempotency keys.

        The marker is written in the same transaction as the replacement, so a
        process interruption can never mark a partial conversion as complete.
        """

        connection = self._require_connection()
        marker = await (
            await connection.execute(
                "SELECT value FROM persistence_metadata WHERE key = ?",
                ("idempotency_keys_sha256_v1",),
            )
        ).fetchone()
        if marker is not None:
            return
        try:
            await connection.execute("BEGIN IMMEDIATE")
            rows = await (
                await connection.execute(
                    "SELECT client_request_id, payload_hash, request_id, created_at "
                    "FROM idempotency_keys"
                )
            ).fetchall()
            await connection.execute("DELETE FROM idempotency_keys")
            for row in rows:
                await connection.execute(
                    "INSERT INTO idempotency_keys "
                    "(client_request_id, payload_hash, request_id, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        self._client_request_id_hash(row["client_request_id"]),
                        row["payload_hash"],
                        row["request_id"],
                        row["created_at"],
                    ),
                )
            await connection.execute(
                "INSERT INTO persistence_metadata(key, value) VALUES (?, ?)",
                ("idempotency_keys_sha256_v1", "complete"),
            )
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise

    @staticmethod
    def _client_request_id_hash(client_request_id: str) -> str:
        digest = hashlib.sha256(client_request_id.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    async def create_session(
        self,
        session: DiagnosisSession,
        *,
        audit_event_type: str | None = None,
        audit_data: dict[str, JsonValue] | None = None,
    ) -> DiagnosisSession:
        connection = self._require_connection()
        safe_metadata = self._sanitize_mapping(session.metadata)
        safe_session = session.model_copy(update={"metadata": safe_metadata})
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                await connection.execute(
                    "INSERT INTO diagnosis_sessions "
                    "(session_id, state, created_at, updated_at, closed_at, metadata_json) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        safe_session.session_id,
                        safe_session.state.value,
                        _timestamp(safe_session.created_at),
                        _timestamp(safe_session.updated_at),
                        _timestamp(safe_session.closed_at) if safe_session.closed_at else None,
                        canonical_json(safe_session.metadata),
                    ),
                )
                if audit_event_type is not None:
                    await self._append_audit_locked(
                        connection,
                        occurred_at=safe_session.created_at,
                        event_type=audit_event_type,
                        request_id=None,
                        session_id=safe_session.session_id,
                        data=audit_data or {},
                    )
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
        return safe_session

    async def get_session(self, session_id: str) -> DiagnosisSession | None:
        connection = self._require_connection()
        async with self._lock:
            return await self._session_locked(connection, session_id)

    async def _session_locked(
        self,
        connection: aiosqlite.Connection,
        session_id: str,
    ) -> DiagnosisSession | None:
        row = await (
            await connection.execute(
                "SELECT * FROM diagnosis_sessions WHERE session_id = ?", (session_id,)
            )
        ).fetchone()
        return self._session_from_row(row) if row is not None else None

    async def list_sessions(self, *, include_closed: bool = True) -> list[DiagnosisSession]:
        connection = self._require_connection()
        async with self._lock:
            return await self._list_sessions_locked(connection, include_closed=include_closed)

    async def _list_sessions_locked(
        self,
        connection: aiosqlite.Connection,
        *,
        include_closed: bool,
    ) -> list[DiagnosisSession]:
        query = "SELECT * FROM diagnosis_sessions"
        parameters: tuple[str, ...] = ()
        if not include_closed:
            query += " WHERE state <> ?"
            parameters = (DiagnosisState.CLOSED.value,)
        query += " ORDER BY created_at DESC"
        rows = await (await connection.execute(query, parameters)).fetchall()
        return [self._session_from_row(row) for row in rows]

    async def update_session_state(
        self,
        session_id: str,
        state: DiagnosisState,
        *,
        at: datetime | None = None,
        audit_event_type: str | None = None,
        audit_data: dict[str, JsonValue] | None = None,
    ) -> DiagnosisSession:
        connection = self._require_connection()
        timestamp = at or utc_now()
        closed_at = timestamp if state is DiagnosisState.CLOSED else None
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                current_row = await (
                    await connection.execute(
                        "SELECT state FROM diagnosis_sessions WHERE session_id = ?",
                        (session_id,),
                    )
                ).fetchone()
                if current_row is None:
                    raise KeyError(session_id)
                if DiagnosisState(current_row["state"]) is not state:
                    await connection.execute(
                        "UPDATE diagnosis_sessions SET state = ?, updated_at = ?, "
                        "closed_at = COALESCE(closed_at, ?) WHERE session_id = ?",
                        (
                            state.value,
                            _timestamp(timestamp),
                            _timestamp(closed_at) if closed_at else None,
                            session_id,
                        ),
                    )
                    if audit_event_type is not None:
                        event_data: dict[str, JsonValue] = {"state": state.value}
                        event_data.update(audit_data or {})
                        await self._append_audit_locked(
                            connection,
                            occurred_at=timestamp,
                            event_type=audit_event_type,
                            request_id=None,
                            session_id=session_id,
                            data=event_data,
                        )
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
        session = await self.get_session(session_id)
        assert session is not None
        return session

    async def close_session(
        self,
        session_id: str,
        *,
        at: datetime | None = None,
        audit_event_type: str | None = None,
        audit_data: dict[str, JsonValue] | None = None,
    ) -> DiagnosisSession:
        return await self.update_session_state(
            session_id,
            DiagnosisState.CLOSED,
            at=at,
            audit_event_type=audit_event_type,
            audit_data=audit_data,
        )

    async def create_action(
        self,
        receipt: ActionReceipt,
        *,
        client_request_id: str,
        payload_hash: str,
        plan: ExecutionPlan | None = None,
        initial_transition: ActionState | None = None,
        initial_transition_detail: dict[str, JsonValue] | None = None,
        initial_transition_audit_data: dict[str, JsonValue] | None = None,
    ) -> tuple[ActionRecord, bool]:
        """Atomically persist an action and its optional initial policy transition.

        The bool is false for a same-key/same-payload retry. A changed payload
        raises IdempotencyConflict and never creates another action. When
        ``initial_transition`` is supplied, RECEIVED and its transition event
        and audit anchor become visible in one commit.
        """

        if not client_request_id:
            raise ValueError("client_request_id must not be empty")
        if not payload_hash.startswith("sha256:"):
            raise ValueError("payload_hash must be a prefixed SHA-256 digest")
        if initial_transition is not None:
            if receipt.status is not ActionState.RECEIVED:
                raise ValueError("an initial transition requires a RECEIVED receipt")
            if initial_transition not in {
                ActionState.PENDING_APPROVAL,
                ActionState.POLICY_REJECTED,
            }:
                raise ValueError("initial_transition must be PENDING_APPROVAL or POLICY_REJECTED")
            require_transition(ActionState.RECEIVED, initial_transition)
        safe_summary = self._sanitize_text(receipt.summary)
        safe_receipt = receipt.model_copy(update={"summary": safe_summary})
        safe_plan = self._sanitize_plan(plan) if plan is not None else None
        if safe_plan is not None:
            self._validate_plan(safe_plan, receipt.request_id)

        connection = self._require_connection()
        opaque_client_request_id = self._client_request_id_hash(client_request_id)
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                existing = await (
                    await connection.execute(
                        "SELECT payload_hash, request_id FROM idempotency_keys "
                        "WHERE client_request_id = ?",
                        (opaque_client_request_id,),
                    )
                ).fetchone()
                if existing is not None:
                    if existing["payload_hash"] != payload_hash:
                        raise IdempotencyConflict()
                    await connection.rollback()
                    record = await self._find_action_locked(connection, existing["request_id"])
                    if record is None:  # pragma: no cover - protected by FK
                        raise RuntimeError("idempotency key references a missing action")
                    return record, False

                created_at = _timestamp(safe_receipt.created_at)
                await connection.execute(
                    "INSERT INTO actions "
                    "(request_id, session_id, tool, target_id, risk, summary, state, created_at, "
                    "updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        safe_receipt.request_id,
                        safe_receipt.session_id,
                        safe_receipt.tool,
                        safe_receipt.target_id,
                        safe_receipt.risk.value,
                        safe_receipt.summary,
                        safe_receipt.status.value,
                        created_at,
                        created_at,
                        _timestamp(safe_receipt.expires_at) if safe_receipt.expires_at else None,
                    ),
                )
                await connection.execute(
                    "INSERT INTO idempotency_keys "
                    "(client_request_id, payload_hash, request_id, created_at) VALUES (?, ?, ?, ?)",
                    (
                        opaque_client_request_id,
                        payload_hash,
                        safe_receipt.request_id,
                        created_at,
                    ),
                )
                await connection.execute(
                    "INSERT INTO action_events "
                    "(request_id, from_state, to_state, occurred_at, detail_json) "
                    "VALUES (?, NULL, ?, ?, '{}')",
                    (safe_receipt.request_id, safe_receipt.status.value, created_at),
                )
                if safe_plan is not None:
                    await self._insert_plan(connection, safe_plan, safe_receipt.created_at)
                await self._append_audit_locked(
                    connection,
                    occurred_at=safe_receipt.created_at,
                    event_type="action.received",
                    request_id=safe_receipt.request_id,
                    session_id=safe_receipt.session_id,
                    data={
                        "tool": safe_receipt.tool,
                        "targetId": safe_receipt.target_id,
                        "argumentsHash": payload_hash,
                        "status": safe_receipt.status.value,
                    },
                )
                if initial_transition is not None:
                    record = await self._transition_action_locked(
                        connection,
                        request_id=safe_receipt.request_id,
                        current=ActionState.RECEIVED,
                        requested=initial_transition,
                        timestamp=safe_receipt.created_at,
                        detail=initial_transition_detail,
                    )
                    transition_data: dict[str, JsonValue] = {
                        "fromState": ActionState.RECEIVED.value,
                        "status": initial_transition.value,
                    }
                    transition_data.update(initial_transition_audit_data or {})
                    await self._append_audit_locked(
                        connection,
                        occurred_at=safe_receipt.created_at,
                        event_type=f"action.{initial_transition.value.lower()}",
                        request_id=safe_receipt.request_id,
                        session_id=safe_receipt.session_id,
                        data=transition_data,
                    )
                else:
                    record = await self._action_locked(connection, safe_receipt.request_id)
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
        return record, True

    async def get_action(self, request_id: str) -> ActionRecord | None:
        connection = self._require_connection()
        async with self._lock:
            return await self._find_action_locked(connection, request_id)

    async def _find_action_locked(
        self,
        connection: aiosqlite.Connection,
        request_id: str,
    ) -> ActionRecord | None:
        row = await (
            await connection.execute("SELECT * FROM actions WHERE request_id = ?", (request_id,))
        ).fetchone()
        return self._action_from_row(row) if row is not None else None

    async def _action_locked(
        self,
        connection: aiosqlite.Connection,
        request_id: str,
    ) -> ActionRecord:
        """Load an action while the caller owns the current write transaction."""

        action = await self._find_action_locked(connection, request_id)
        if action is None:
            raise KeyError(request_id)
        return action

    async def _transition_action_locked(
        self,
        connection: aiosqlite.Connection,
        *,
        request_id: str,
        current: ActionState,
        requested: ActionState,
        timestamp: datetime,
        error: NormalizedError | None = None,
        detail: dict[str, JsonValue] | None = None,
    ) -> ActionRecord:
        """Apply one compare-and-swap state transition inside a transaction."""

        actual = await self._action_locked(connection, request_id)
        if actual.status is not current:
            # Raise the same typed state-machine error as every public transition.
            require_transition(actual.status, requested)
            raise RuntimeError(
                f"action state changed concurrently from {current.value} to {actual.status.value}"
            )
        require_transition(current, requested)
        safe_detail = self._sanitize_mapping(detail or {})
        safe_error = self._sanitize_error(error) if error is not None else None
        started_at = _timestamp(timestamp) if requested is ActionState.EXECUTING else None
        finished_at = _timestamp(timestamp) if requested in TERMINAL_ACTION_STATES else None
        cursor = await connection.execute(
            "UPDATE actions SET state = ?, updated_at = ?, "
            "started_at = COALESCE(started_at, ?), finished_at = COALESCE(finished_at, ?), "
            "error_json = ? WHERE request_id = ? AND state = ?",
            (
                requested.value,
                _timestamp(timestamp),
                started_at,
                finished_at,
                canonical_json(safe_error) if safe_error is not None else None,
                request_id,
                current.value,
            ),
        )
        if cursor.rowcount != 1:  # pragma: no cover - serialized transaction invariant
            raise RuntimeError("action state compare-and-swap failed")
        await connection.execute(
            "INSERT INTO action_events "
            "(request_id, from_state, to_state, occurred_at, detail_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                request_id,
                current.value,
                requested.value,
                _timestamp(timestamp),
                canonical_json(safe_detail),
            ),
        )
        return await self._action_locked(connection, request_id)

    async def approve_and_start_action(
        self,
        request_id: str,
        expected_action_hash: str,
        *,
        at: datetime | None = None,
        approver: str | None = None,
        precondition: Callable[[ExecutionPlan], bool] | None = None,
    ) -> StartActionResult:
        """Atomically consume one approval and enter EXECUTING.

        The caller first validates current target and policy configuration using
        the persisted plan, then supplies that plan's hash here. SQLite performs
        the final state/deadline/session/hash compare-and-swap so no APPROVED
        state is externally observable or stranded by task scheduling.
        """

        timestamp = at or utc_now()
        connection = self._require_connection()
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                row = await (
                    await connection.execute(
                        "SELECT a.*, s.state AS session_state, "
                        "p.plan_json AS plan_json, p.action_hash AS stored_action_hash "
                        "FROM actions a "
                        "JOIN diagnosis_sessions s ON s.session_id = a.session_id "
                        "LEFT JOIN execution_plans p ON p.request_id = a.request_id "
                        "WHERE a.request_id = ?",
                        (request_id,),
                    )
                ).fetchone()
                if row is None:
                    await connection.rollback()
                    return StartActionResult(
                        outcome=StartActionOutcome.NOT_FOUND,
                        error=NormalizedError(
                            code=ErrorCode.INVALID_ARGUMENT,
                            message="The action request ID does not exist.",
                        ),
                    )

                action = self._action_from_row(row)
                if action.status is not ActionState.PENDING_APPROVAL:
                    await connection.rollback()
                    return StartActionResult(
                        outcome=StartActionOutcome.NON_PENDING,
                        action=action,
                        error=NormalizedError(
                            code=ErrorCode.INVALID_ARGUMENT,
                            message=f"Action is {action.status.value} and cannot be approved.",
                        ),
                    )

                if action.expires_at is not None and action.expires_at <= timestamp:
                    await self._transition_action_locked(
                        connection,
                        request_id=request_id,
                        current=ActionState.PENDING_APPROVAL,
                        requested=ActionState.EXPIRED,
                        timestamp=timestamp,
                        detail={"reason": "approval_timeout"},
                    )
                    audit = await self._append_audit_locked(
                        connection,
                        occurred_at=timestamp,
                        event_type="action.expired",
                        request_id=request_id,
                        session_id=action.session_id,
                        data={"reason": "approval_timeout", "status": "EXPIRED"},
                    )
                    updated = await self._action_locked(connection, request_id)
                    await connection.commit()
                    return StartActionResult(
                        outcome=StartActionOutcome.EXPIRED,
                        action=updated,
                        error=NormalizedError(
                            code=ErrorCode.APPROVAL_EXPIRED,
                            message="The approval deadline has expired.",
                        ),
                        audit_entry=audit,
                    )

                if DiagnosisState(row["session_state"]) is DiagnosisState.CLOSED:
                    error = NormalizedError(
                        code=ErrorCode.CANCELLED,
                        message="The diagnosis session was closed before approval.",
                    )
                    result = self._sanitize_result(
                        ActionResult(
                            request_id=request_id,
                            status=ActionState.CANCELLED,
                            tool=action.tool,
                            target_id=action.target_id,
                            finished_at=timestamp,
                            duration_ms=0,
                            error=error,
                        )
                    )
                    result_hash = await self._insert_result_locked(connection, result)
                    await self._transition_action_locked(
                        connection,
                        request_id=request_id,
                        current=ActionState.PENDING_APPROVAL,
                        requested=ActionState.CANCELLED,
                        timestamp=timestamp,
                        error=error,
                        detail={"reason": "session_closed", "resultHash": result_hash},
                    )
                    audit = await self._append_audit_locked(
                        connection,
                        occurred_at=timestamp,
                        event_type="action.cancelled",
                        request_id=request_id,
                        session_id=action.session_id,
                        data=self._result_audit_data(
                            result,
                            result_hash,
                            extra={"reason": "session_closed"},
                        ),
                    )
                    updated = await self._action_locked(connection, request_id)
                    await connection.commit()
                    return StartActionResult(
                        outcome=StartActionOutcome.SESSION_CLOSED,
                        action=updated,
                        error=error,
                        audit_entry=audit,
                    )

                plan: ExecutionPlan | None = None
                try:
                    if row["plan_json"] is None:
                        raise ValueError("missing plan")
                    plan = ExecutionPlan.model_validate_json(row["plan_json"])
                    if (
                        not plan.verify_hash()
                        or plan.action_hash != row["stored_action_hash"]
                        or plan.action_hash != expected_action_hash
                    ):
                        raise ValueError("plan hash mismatch")
                except (TypeError, ValueError):
                    await self._transition_action_locked(
                        connection,
                        request_id=request_id,
                        current=ActionState.PENDING_APPROVAL,
                        requested=ActionState.EXPIRED,
                        timestamp=timestamp,
                        detail={"reason": "plan_mismatch"},
                    )
                    audit = await self._append_audit_locked(
                        connection,
                        occurred_at=timestamp,
                        event_type="action.expired",
                        request_id=request_id,
                        session_id=action.session_id,
                        data={"reason": "plan_mismatch", "status": "EXPIRED"},
                    )
                    updated = await self._action_locked(connection, request_id)
                    await connection.commit()
                    return StartActionResult(
                        outcome=StartActionOutcome.PLAN_MISMATCH,
                        action=updated,
                        error=NormalizedError(
                            code=ErrorCode.APPROVAL_EXPIRED,
                            message="The execution plan no longer matches the reviewed plan.",
                        ),
                        audit_entry=audit,
                    )

                assert plan is not None
                configuration_is_current = True
                if precondition is not None:
                    try:
                        configuration_is_current = precondition(plan) is True
                    except Exception:
                        configuration_is_current = False
                if not configuration_is_current:
                    await self._transition_action_locked(
                        connection,
                        request_id=request_id,
                        current=ActionState.PENDING_APPROVAL,
                        requested=ActionState.EXPIRED,
                        timestamp=timestamp,
                        detail={"reason": "configuration_changed"},
                    )
                    audit = await self._append_audit_locked(
                        connection,
                        occurred_at=timestamp,
                        event_type="action.expired",
                        request_id=request_id,
                        session_id=action.session_id,
                        data={"reason": "configuration_changed", "status": "EXPIRED"},
                    )
                    updated = await self._action_locked(connection, request_id)
                    await connection.commit()
                    return StartActionResult(
                        outcome=StartActionOutcome.CONFIGURATION_CHANGED,
                        action=updated,
                        error=NormalizedError(
                            code=ErrorCode.APPROVAL_EXPIRED,
                            message=(
                                "The target, policy, or executor configuration changed "
                                "after review."
                            ),
                        ),
                        audit_entry=audit,
                    )

                await self._transition_action_locked(
                    connection,
                    request_id=request_id,
                    current=ActionState.PENDING_APPROVAL,
                    requested=ActionState.APPROVED,
                    timestamp=timestamp,
                    detail={"actionHash": expected_action_hash},
                )
                await self._transition_action_locked(
                    connection,
                    request_id=request_id,
                    current=ActionState.APPROVED,
                    requested=ActionState.EXECUTING,
                    timestamp=timestamp,
                    detail={"actionHash": expected_action_hash},
                )
                audit_data: dict[str, JsonValue] = {
                    "actionHash": expected_action_hash,
                    "status": "EXECUTING",
                }
                if approver:
                    audit_data["approver"] = approver
                audit = await self._append_audit_locked(
                    connection,
                    occurred_at=timestamp,
                    event_type="action.approved",
                    request_id=request_id,
                    session_id=action.session_id,
                    data=audit_data,
                )
                updated = await self._action_locked(connection, request_id)
                await connection.commit()
                return StartActionResult(
                    outcome=StartActionOutcome.STARTED,
                    action=updated,
                    plan=plan,
                    audit_entry=audit,
                )
            except BaseException:
                await connection.rollback()
                raise

    async def list_actions(
        self,
        *,
        session_id: str | None = None,
        state: ActionState | None = None,
        limit: int = 100,
    ) -> list[ActionRecord]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        connection = self._require_connection()
        async with self._lock:
            return await self._list_actions_locked(
                connection,
                session_id=session_id,
                state=state,
                limit=limit,
            )

    async def _list_actions_locked(
        self,
        connection: aiosqlite.Connection,
        *,
        session_id: str | None,
        state: ActionState | None,
        limit: int,
    ) -> list[ActionRecord]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            parameters.append(session_id)
        if state is not None:
            clauses.append("state = ?")
            parameters.append(state.value)
        query = "SELECT * FROM actions"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)
        rows = await (await connection.execute(query, parameters)).fetchall()
        return [self._action_from_row(row) for row in rows]

    async def transition_action(
        self,
        request_id: str,
        requested: ActionState,
        *,
        at: datetime | None = None,
        error: NormalizedError | None = None,
        detail: dict[str, JsonValue] | None = None,
        audit_event_type: str | None = None,
        audit_data: dict[str, JsonValue] | None = None,
    ) -> ActionRecord:
        connection = self._require_connection()
        timestamp = at or utc_now()
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                current_action = await self._action_locked(connection, request_id)
                record = await self._transition_action_locked(
                    connection,
                    request_id=request_id,
                    current=current_action.status,
                    requested=requested,
                    timestamp=timestamp,
                    error=error,
                    detail=detail,
                )
                if audit_event_type is not None:
                    event_data: dict[str, JsonValue] = {
                        "fromState": current_action.status.value,
                        "status": requested.value,
                    }
                    event_data.update(audit_data or {})
                    await self._append_audit_locked(
                        connection,
                        occurred_at=timestamp,
                        event_type=audit_event_type,
                        request_id=request_id,
                        session_id=current_action.session_id,
                        data=event_data,
                    )
                await connection.commit()
                return record
            except BaseException:
                await connection.rollback()
                raise

    async def action_events(self, request_id: str) -> list[ActionEvent]:
        connection = self._require_connection()
        async with self._lock:
            return await self._action_events_locked(connection, request_id)

    async def _action_events_locked(
        self,
        connection: aiosqlite.Connection,
        request_id: str,
    ) -> list[ActionEvent]:
        rows = await (
            await connection.execute(
                "SELECT * FROM action_events WHERE request_id = ? ORDER BY event_id", (request_id,)
            )
        ).fetchall()
        return [
            ActionEvent(
                event_id=row["event_id"],
                request_id=row["request_id"],
                from_state=row["from_state"],
                to_state=row["to_state"],
                occurred_at=_required_timestamp(row["occurred_at"]),
                detail=_decode_json(row["detail_json"]),
            )
            for row in rows
        ]

    async def expire_actions(self, *, now: datetime | None = None) -> int:
        timestamp = now or utc_now()
        connection = self._require_connection()
        count = 0
        while True:
            async with self._lock:
                try:
                    await connection.execute("BEGIN IMMEDIATE")
                    rows = list(
                        await (
                            await connection.execute(
                                "SELECT * FROM actions WHERE state = ? "
                                "AND expires_at IS NOT NULL AND expires_at <= ? LIMIT 1000",
                                (ActionState.PENDING_APPROVAL.value, _timestamp(timestamp)),
                            )
                        ).fetchall()
                    )
                    for row in rows:
                        action = self._action_from_row(row)
                        await self._transition_action_locked(
                            connection,
                            request_id=action.request_id,
                            current=ActionState.PENDING_APPROVAL,
                            requested=ActionState.EXPIRED,
                            timestamp=timestamp,
                            detail={"reason": "approval_timeout"},
                        )
                        await self._append_audit_locked(
                            connection,
                            occurred_at=timestamp,
                            event_type="action.expired",
                            request_id=action.request_id,
                            session_id=action.session_id,
                            data={"reason": "approval_timeout", "status": "EXPIRED"},
                        )
                    await connection.commit()
                except BaseException:
                    await connection.rollback()
                    raise
            count += len(rows)
            if len(rows) < 1000:
                return count

    async def reconcile_incomplete_actions(self, *, at: datetime | None = None) -> int:
        """Fail closed after a restart without executing an action again.

        Legacy RECEIVED rows are policy-rejected because no durable policy
        decision exists. APPROVED/EXECUTING rows receive a terminal result.
        """

        timestamp = at or utc_now()
        error = NormalizedError(
            code=ErrorCode.EXECUTION_FAILED,
            message="Execution was interrupted by a Terminal Server restart.",
            next_step="Create a new request and approve it again if the test is still needed.",
            retryable=False,
        )
        connection = self._require_connection()
        count = 0
        while True:
            async with self._lock:
                try:
                    await connection.execute("BEGIN IMMEDIATE")
                    rows = list(
                        await (
                            await connection.execute(
                                "SELECT * FROM actions WHERE state IN (?, ?, ?) "
                                "ORDER BY created_at LIMIT 1000",
                                (
                                    ActionState.RECEIVED.value,
                                    ActionState.APPROVED.value,
                                    ActionState.EXECUTING.value,
                                ),
                            )
                        ).fetchall()
                    )
                    for row in rows:
                        action = self._action_from_row(row)
                        if action.status is ActionState.RECEIVED:
                            await self._transition_action_locked(
                                connection,
                                request_id=action.request_id,
                                current=ActionState.RECEIVED,
                                requested=ActionState.POLICY_REJECTED,
                                timestamp=timestamp,
                                detail={"reason": "crash_reconciliation_received"},
                            )
                            await self._append_audit_locked(
                                connection,
                                occurred_at=timestamp,
                                event_type="action.policy_rejected",
                                request_id=action.request_id,
                                session_id=action.session_id,
                                data={
                                    "reason": "crash_reconciliation_received",
                                    "status": ActionState.POLICY_REJECTED.value,
                                },
                            )
                            continue
                        if action.status is ActionState.APPROVED:
                            action = await self._transition_action_locked(
                                connection,
                                request_id=action.request_id,
                                current=ActionState.APPROVED,
                                requested=ActionState.EXECUTING,
                                timestamp=timestamp,
                                detail={"reason": "crash_reconciliation_no_execution"},
                            )
                        assert action.started_at is not None
                        persisted = await self._result_locked(connection, action.request_id)
                        if persisted is None:
                            duration_ms = max(
                                0,
                                int((timestamp - action.started_at).total_seconds() * 1000),
                            )
                            result = self._sanitize_result(
                                ActionResult(
                                    request_id=action.request_id,
                                    status=ActionState.FAILED,
                                    tool=action.tool,
                                    target_id=action.target_id,
                                    started_at=action.started_at,
                                    finished_at=timestamp,
                                    duration_ms=duration_ms,
                                    error=error,
                                )
                            )
                        else:
                            result = persisted
                            if result.tool != action.tool or result.target_id != action.target_id:
                                raise ValueError(
                                    "persisted result identity does not match stranded action"
                                )
                            if result.finished_at < action.started_at:
                                raise ValueError("persisted result predates stranded action")
                        result_hash = await self._insert_result_locked(connection, result)
                        metadata = self._result_audit_data(
                            result,
                            result_hash,
                            extra={"reason": "crash_reconciliation", "reexecuted": False},
                        )
                        await self._transition_action_locked(
                            connection,
                            request_id=action.request_id,
                            current=ActionState.EXECUTING,
                            requested=result.status,
                            timestamp=result.finished_at,
                            error=result.error,
                            detail={
                                "reason": "crash_reconciliation",
                                "resultHash": result_hash,
                            },
                        )
                        await self._append_audit_locked(
                            connection,
                            occurred_at=result.finished_at,
                            event_type=f"action.{result.status.value.lower()}",
                            request_id=action.request_id,
                            session_id=action.session_id,
                            data=metadata,
                        )
                    await connection.commit()
                except BaseException:
                    await connection.rollback()
                    raise
            count += len(rows)
            if len(rows) < 1000:
                return count

    async def store_execution_plan(self, plan: ExecutionPlan) -> ExecutionPlan:
        self._validate_plan(plan, plan.request_id)
        safe_plan = self._sanitize_plan(plan)
        connection = self._require_connection()
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                await self._insert_plan(connection, safe_plan, utc_now())
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
        return safe_plan

    async def _insert_plan(
        self,
        connection: aiosqlite.Connection,
        plan: ExecutionPlan,
        created_at: datetime,
    ) -> None:
        assert plan.action_hash is not None
        await connection.execute(
            "INSERT INTO execution_plans "
            "(request_id, plan_json, action_hash, policy_version, target_version, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                plan.request_id,
                canonical_json(plan),
                plan.action_hash,
                plan.policy_version,
                plan.target_version,
                _timestamp(created_at),
            ),
        )

    def _validate_plan(self, plan: ExecutionPlan, request_id: str) -> None:
        if plan.request_id != request_id:
            raise ValueError("plan requestId does not match action")
        if not plan.verify_hash():
            raise ValueError("execution plan has a missing or invalid actionHash")

    def _sanitize_text(self, value: str) -> str:
        sanitized = self.sanitizer.sanitize(value)
        if isinstance(sanitized.data, str):
            return sanitized.data
        return canonical_json(sanitized.data)

    def _sanitize_error(self, error: NormalizedError) -> NormalizedError:
        sanitized = self.sanitizer.sanitize(error)
        if not isinstance(sanitized.data, dict):
            return NormalizedError(
                code=ErrorCode.INTERNAL_ERROR,
                message="Error details exceeded safe persistence limits.",
            )
        return NormalizedError.model_validate(sanitized.data)

    def _sanitize_mapping(self, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        sanitized = self.sanitizer.sanitize(value)
        if isinstance(sanitized.data, dict):
            safe: dict[str, JsonValue] = sanitized.data
        else:
            safe = {"sanitizedOutput": sanitized.data}
        if sanitized.redactions:
            safe["_redactions"] = cast(JsonValue, self._safe_redaction_labels(sanitized.redactions))
        if sanitized.truncated:
            safe["_truncated"] = True
        return safe

    @staticmethod
    def _safe_redaction_labels(labels: list[str]) -> list[str]:
        # Labels are metadata exposed back to clients and written to audit.
        # Treat executor-supplied values as secrets themselves and retain only
        # the fixed vocabulary emitted by Sanitizer.
        return sorted(
            {
                normalized
                for label in labels
                if (normalized := label.casefold()) in _TRUSTED_REDACTION_LABELS
            }
        )

    def _sanitize_plan(self, plan: ExecutionPlan) -> ExecutionPlan:
        payload = plan.model_dump(mode="json", by_alias=True, exclude={"action_hash"})
        sanitized = self.sanitizer.sanitize(payload)
        if not isinstance(sanitized.data, dict):
            raise ValueError("execution plan exceeds safe persistence limits")
        safe_plan = ExecutionPlan.model_validate(sanitized.data)
        return safe_plan.with_calculated_hash()

    async def load_execution_plan(self, request_id: str) -> ExecutionPlan | None:
        connection = self._require_connection()
        async with self._lock:
            return await self._load_execution_plan_locked(connection, request_id)

    async def _load_execution_plan_locked(
        self,
        connection: aiosqlite.Connection,
        request_id: str,
    ) -> ExecutionPlan | None:
        row = await (
            await connection.execute(
                "SELECT plan_json FROM execution_plans WHERE request_id = ?", (request_id,)
            )
        ).fetchone()
        if row is None:
            return None
        plan = ExecutionPlan.model_validate_json(row["plan_json"])
        if not plan.verify_hash():
            raise ValueError("persisted execution plan failed hash verification")
        return plan

    async def store_result(self, result: ActionResult) -> str:
        """Persist an already-terminal result without changing action state.

        New execution code should prefer :meth:`finalize_action`, which commits
        the result, state transition, action event, and audit anchor atomically.
        This method remains for reading/migration compatibility.
        """

        result = self._sanitize_result(result)
        connection = self._require_connection()
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                result_hash = await self._insert_result_locked(connection, result)
                await connection.commit()
                return result_hash
            except BaseException:
                await connection.rollback()
                raise

    async def _insert_result_locked(
        self,
        connection: aiosqlite.Connection,
        result: ActionResult,
    ) -> str:
        """Insert one immutable, sanitized result in the current transaction."""

        result_hash = canonical_sha256(result)
        existing = await (
            await connection.execute(
                "SELECT result_json, result_hash FROM sanitized_results WHERE request_id = ?",
                (result.request_id,),
            )
        ).fetchone()
        if existing is not None:
            try:
                persisted = ActionResult.model_validate_json(existing["result_json"])
            except (TypeError, ValueError) as exc:
                raise ValueError("persisted result is malformed") from exc
            if (
                existing["result_hash"] != result_hash
                or canonical_sha256(persisted) != existing["result_hash"]
            ):
                raise ValueError("a different result is already stored for this action")
            return result_hash
        await connection.execute(
            "INSERT INTO sanitized_results"
            "(request_id, result_json, result_hash, created_at) VALUES (?, ?, ?, ?)",
            (
                result.request_id,
                canonical_json(result),
                result_hash,
                _timestamp(result.finished_at),
            ),
        )
        return result_hash

    def _result_audit_data(
        self,
        result: ActionResult,
        result_hash: str,
        *,
        extra: dict[str, JsonValue] | None = None,
    ) -> dict[str, JsonValue]:
        """Create bounded audit metadata without copying executor output."""

        data: dict[str, JsonValue] = {
            "status": result.status.value,
            "resultHash": result_hash,
            "redactions": cast(JsonValue, self._safe_redaction_labels(result.redactions)),
            "truncated": result.truncated,
            "durationMs": result.duration_ms,
        }
        if result.error is not None:
            data["error"] = cast(
                JsonValue,
                result.error.model_dump(mode="json", by_alias=True),
            )
        data.update(extra or {})
        return self._sanitize_mapping(data)

    async def finalize_action(
        self,
        result: ActionResult,
        *,
        audit_event_type: str | None = None,
        audit_data: dict[str, JsonValue] | None = None,
    ) -> FinalizedAction:
        """Atomically persist a result and move EXECUTING to its terminal state."""

        safe_result = self._sanitize_result(result)
        connection = self._require_connection()
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                action = await self._action_locked(connection, safe_result.request_id)
                if action.status is not ActionState.EXECUTING:
                    require_transition(action.status, safe_result.status)
                    raise RuntimeError(
                        "only an EXECUTING action can be finalized with an execution result"
                    )
                if safe_result.tool != action.tool or safe_result.target_id != action.target_id:
                    raise ValueError("result identity does not match the persisted action")
                if action.started_at is None:  # pragma: no cover - schema/state invariant
                    raise ValueError("executing action has no start timestamp")
                if safe_result.finished_at < action.started_at:
                    raise ValueError("result finishedAt precedes action start")
                safe_result = safe_result.model_copy(update={"started_at": action.started_at})
                result_hash = await self._insert_result_locked(connection, safe_result)
                result_metadata = self._result_audit_data(
                    safe_result,
                    result_hash,
                    extra=audit_data,
                )
                updated = await self._transition_action_locked(
                    connection,
                    request_id=action.request_id,
                    current=ActionState.EXECUTING,
                    requested=safe_result.status,
                    timestamp=safe_result.finished_at,
                    error=safe_result.error,
                    detail={
                        "resultHash": result_hash,
                        "truncated": safe_result.truncated,
                        "durationMs": safe_result.duration_ms,
                    },
                )
                audit = await self._append_audit_locked(
                    connection,
                    occurred_at=safe_result.finished_at,
                    event_type=audit_event_type or f"action.{safe_result.status.value.lower()}",
                    request_id=action.request_id,
                    session_id=action.session_id,
                    data=result_metadata,
                )
                await connection.commit()
                return FinalizedAction(
                    action=updated,
                    result=safe_result,
                    result_hash=result_hash,
                    audit_entry=audit,
                )
            except BaseException:
                await connection.rollback()
                raise

    def _sanitize_result(self, result: ActionResult) -> ActionResult:
        """Defense in depth: SQLite never receives a raw executor result."""

        payload = self.sanitizer.sanitize(
            {"data": result.data, "warnings": result.warnings, "error": result.error}
        )
        if not isinstance(payload.data, dict):
            updates: dict[str, Any] = {
                "data": payload.data,
                "warnings": [],
                "error": None,
            }
        else:
            safe_warnings = payload.data.get("warnings", [])
            updates = {
                "data": payload.data.get("data"),
                "warnings": (
                    [str(item) for item in safe_warnings] if isinstance(safe_warnings, list) else []
                ),
                "error": payload.data.get("error"),
            }
        updates["redactions"] = sorted(
            set(self._safe_redaction_labels(result.redactions))
            | set(self._safe_redaction_labels(payload.redactions))
        )
        updates["truncated"] = result.truncated or payload.truncated
        values = result.model_dump(mode="python", by_alias=False)
        values.update(updates)
        return ActionResult.model_validate(values)

    async def get_result(self, request_id: str) -> ActionResult | None:
        connection = self._require_connection()
        async with self._lock:
            return await self._result_locked(connection, request_id)

    async def _result_locked(
        self,
        connection: aiosqlite.Connection,
        request_id: str,
    ) -> ActionResult | None:
        row = await (
            await connection.execute(
                "SELECT result_json, result_hash FROM sanitized_results WHERE request_id = ?",
                (request_id,),
            )
        ).fetchone()
        if row is None:
            return None
        result = ActionResult.model_validate_json(row["result_json"])
        if canonical_sha256(result) != row["result_hash"]:
            raise ValueError("persisted result failed hash verification")
        return result

    async def integrity_check(self) -> tuple[str, ...]:
        connection = self._require_connection()
        async with self._lock:
            rows = await (await connection.execute("PRAGMA integrity_check")).fetchall()
            return tuple(str(row[0]) for row in rows)

    async def append_audit_event(
        self,
        event_type: str,
        *,
        occurred_at: datetime | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        data: dict[str, JsonValue] | None = None,
    ) -> StoredAuditEntry:
        """Append one hash-chained event under a cross-connection SQLite write lock."""

        connection = self._require_connection()
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                entry = await self._append_audit_locked(
                    connection,
                    occurred_at=occurred_at or utc_now(),
                    event_type=event_type,
                    request_id=request_id,
                    session_id=session_id,
                    data=data or {},
                )
                await connection.commit()
                return entry
            except BaseException:
                await connection.rollback()
                raise

    async def _append_audit_locked(
        self,
        connection: aiosqlite.Connection,
        *,
        occurred_at: datetime,
        event_type: str,
        request_id: str | None,
        session_id: str | None,
        data: dict[str, JsonValue],
    ) -> StoredAuditEntry:
        if _AUDIT_EVENT_TYPE.fullmatch(event_type) is None:
            raise ValueError("invalid audit event type")
        previous_row = await (
            await connection.execute("SELECT * FROM audit_entries ORDER BY sequence DESC LIMIT 1")
        ).fetchone()
        previous = self._audit_from_row(previous_row) if previous_row is not None else None
        entry = StoredAuditEntry(
            sequence=1 if previous is None else previous.sequence + 1,
            occurred_at=occurred_at,
            event_type=event_type,
            request_id=request_id,
            session_id=session_id,
            data=self._sanitize_mapping(data),
            previous_hash=AUDIT_GENESIS_HASH if previous is None else previous.entry_hash,
            entry_hash=AUDIT_GENESIS_HASH,
        ).with_calculated_hash()
        await connection.execute(
            "INSERT INTO audit_entries "
            "(sequence, occurred_at, event_type, request_id, session_id, data_json, "
            "previous_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.sequence,
                _timestamp(entry.occurred_at),
                entry.event_type,
                entry.request_id,
                entry.session_id,
                canonical_json(entry.data),
                entry.previous_hash,
                entry.entry_hash,
            ),
        )
        return entry

    async def raw_audit_rows(self) -> list[dict[str, Any]]:
        connection = self._require_connection()
        async with self._lock:
            return await self._raw_audit_rows_locked(connection)

    async def _raw_audit_rows_locked(
        self,
        connection: aiosqlite.Connection,
    ) -> list[dict[str, Any]]:
        rows = await (
            await connection.execute("SELECT * FROM audit_entries ORDER BY sequence")
        ).fetchall()
        return [dict(row) for row in rows]

    async def integrity_trigger_names(self) -> frozenset[str]:
        connection = self._require_connection()
        async with self._lock:
            return await self._integrity_trigger_names_locked(connection)

    async def _integrity_trigger_names_locked(
        self,
        connection: aiosqlite.Connection,
    ) -> frozenset[str]:
        rows = await (
            await connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        ).fetchall()
        return frozenset(str(row["name"]) for row in rows)

    async def audit_trigger_names(self) -> frozenset[str]:
        """Backward-compatible alias for integrity trigger inspection."""

        connection = self._require_connection()
        async with self._lock:
            return await self._integrity_trigger_names_locked(connection)

    async def last_audit_entry(self) -> StoredAuditEntry | None:
        connection = self._require_connection()
        async with self._lock:
            return await self._last_audit_entry_locked(connection)

    async def _last_audit_entry_locked(
        self,
        connection: aiosqlite.Connection,
    ) -> StoredAuditEntry | None:
        row = await (
            await connection.execute("SELECT * FROM audit_entries ORDER BY sequence DESC LIMIT 1")
        ).fetchone()
        return self._audit_from_row(row) if row is not None else None

    async def insert_audit_entry(self, entry: StoredAuditEntry) -> None:
        """Import a pre-built audit entry only when it exactly extends the chain."""

        if entry.calculate_hash() != entry.entry_hash:
            raise ValueError("audit entry hash does not match its content")
        connection = self._require_connection()
        async with self._lock:
            try:
                await connection.execute("BEGIN IMMEDIATE")
                previous_row = await (
                    await connection.execute(
                        "SELECT * FROM audit_entries ORDER BY sequence DESC LIMIT 1"
                    )
                ).fetchone()
                previous = self._audit_from_row(previous_row) if previous_row is not None else None
                expected_sequence = 1 if previous is None else previous.sequence + 1
                expected_previous = AUDIT_GENESIS_HASH if previous is None else previous.entry_hash
                if entry.sequence != expected_sequence or entry.previous_hash != expected_previous:
                    raise ValueError("audit entry does not extend the current chain")
                await connection.execute(
                    "INSERT INTO audit_entries "
                    "(sequence, occurred_at, event_type, request_id, session_id, data_json, "
                    "previous_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry.sequence,
                        _timestamp(entry.occurred_at),
                        entry.event_type,
                        entry.request_id,
                        entry.session_id,
                        canonical_json(entry.data),
                        entry.previous_hash,
                        entry.entry_hash,
                    ),
                )
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise

    async def list_audit_entries(self) -> list[StoredAuditEntry]:
        connection = self._require_connection()
        async with self._lock:
            return await self._list_audit_entries_locked(connection)

    async def _list_audit_entries_locked(
        self,
        connection: aiosqlite.Connection,
    ) -> list[StoredAuditEntry]:
        rows = await (
            await connection.execute("SELECT * FROM audit_entries ORDER BY sequence")
        ).fetchall()
        return [self._audit_from_row(row) for row in rows]

    async def get_known_host(
        self, target_id: str, hostname: str, port: int
    ) -> KnownHostFingerprint | None:
        connection = self._require_connection()
        async with self._lock:
            return await self._get_known_host_locked(connection, target_id, hostname, port)

    async def _get_known_host_locked(
        self,
        connection: aiosqlite.Connection,
        target_id: str,
        hostname: str,
        port: int,
    ) -> KnownHostFingerprint | None:
        row = await (
            await connection.execute(
                "SELECT * FROM known_host_fingerprints "
                "WHERE target_id = ? AND hostname = ? AND port = ?",
                (target_id, hostname, port),
            )
        ).fetchone()
        return self._known_host_from_row(row) if row is not None else None

    async def store_known_host(
        self,
        *,
        target_id: str,
        hostname: str,
        port: int,
        fingerprint: str,
        at: datetime | None = None,
    ) -> KnownHostFingerprint:
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        connection = self._require_connection()
        timestamp = at or utc_now()
        async with self._lock:
            await connection.execute(
                "INSERT INTO known_host_fingerprints "
                "(target_id, hostname, port, fingerprint, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(target_id, hostname, port) DO UPDATE SET "
                "fingerprint = excluded.fingerprint, updated_at = excluded.updated_at",
                (
                    target_id,
                    hostname,
                    port,
                    fingerprint,
                    _timestamp(timestamp),
                    _timestamp(timestamp),
                ),
            )
            await connection.commit()
        result = await self.get_known_host(target_id, hostname, port)
        assert result is not None
        return result

    @staticmethod
    def _session_from_row(row: aiosqlite.Row) -> DiagnosisSession:
        return DiagnosisSession(
            session_id=row["session_id"],
            state=DiagnosisState(row["state"]),
            created_at=_required_timestamp(row["created_at"]),
            updated_at=_required_timestamp(row["updated_at"]),
            closed_at=_parse_timestamp(row["closed_at"]),
            metadata=_decode_json(row["metadata_json"]),
        )

    @staticmethod
    def _action_from_row(row: aiosqlite.Row) -> ActionRecord:
        return ActionRecord(
            request_id=row["request_id"],
            session_id=row["session_id"],
            status=ActionState(row["state"]),
            risk=row["risk"],
            summary=row["summary"],
            tool=row["tool"],
            target_id=row["target_id"],
            created_at=_required_timestamp(row["created_at"]),
            expires_at=_parse_timestamp(row["expires_at"]),
            updated_at=_required_timestamp(row["updated_at"]),
            started_at=_parse_timestamp(row["started_at"]),
            finished_at=_parse_timestamp(row["finished_at"]),
            error=_decode_json(row["error_json"]),
        )

    @staticmethod
    def _audit_from_row(row: aiosqlite.Row) -> StoredAuditEntry:
        return StoredAuditEntry(
            sequence=row["sequence"],
            occurred_at=_required_timestamp(row["occurred_at"]),
            event_type=row["event_type"],
            request_id=row["request_id"],
            session_id=row["session_id"],
            data=_decode_json(row["data_json"]),
            previous_hash=row["previous_hash"],
            entry_hash=row["entry_hash"],
        )

    @staticmethod
    def _known_host_from_row(row: aiosqlite.Row) -> KnownHostFingerprint:
        return KnownHostFingerprint(
            target_id=row["target_id"],
            hostname=row["hostname"],
            port=row["port"],
            fingerprint=row["fingerprint"],
            created_at=_required_timestamp(row["created_at"]),
            updated_at=_required_timestamp(row["updated_at"]),
        )
