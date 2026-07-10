from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from diagnose.audit import GENESIS_HASH, AuditLog
from diagnose.persistence import Database


@pytest.mark.asyncio
async def test_audit_is_sanitized_hash_chained_and_verified(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as db:
        audit = AuditLog(db)
        first = await audit.append(
            "action.created",
            request_id="REQ-test",
            session_id="DIAG-test",
            data={"authorization": "Bearer secret", "command": "safe"},
        )
        second = await audit.append(
            "action.approved", request_id="REQ-test", data={"approver": "local-user"}
        )

        verification = await audit.verify()

        assert first.previous_hash == GENESIS_HASH
        assert second.previous_hash == first.entry_hash
        assert first.data["authorization"] == "[REDACTED]"
        assert verification.valid
        assert verification.entries_checked == 2


@pytest.mark.asyncio
async def test_audit_table_rejects_update_and_verifier_detects_external_tampering(
    tmp_path: Path,
) -> None:
    path = tmp_path / "diagnose.sqlite3"
    db = Database(path)
    await db.initialize()
    await AuditLog(db).append("action.created", data={"summary": "original"})
    await db.close()

    connection = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE audit_entries SET data_json = '{}' WHERE sequence = 1")
    connection.rollback()
    connection.execute("DROP TRIGGER audit_entries_no_update")
    connection.execute("UPDATE audit_entries SET data_json = '{}' WHERE sequence = 1")
    connection.commit()
    connection.close()

    async with Database(path) as reopened:
        verification = await AuditLog(reopened).verify()
        assert not verification.valid
        assert any("hash does not match" in error for error in verification.errors)
