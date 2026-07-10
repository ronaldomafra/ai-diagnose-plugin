from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from diagnose.audit import AuditLog
from diagnose.persistence import Database


@pytest.mark.asyncio
async def test_audit_trigger_blocks_insert_or_replace(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        await AuditLog(database).append("test.first", data={"safe": True})
        connection = database._require_connection()

        with pytest.raises(sqlite3.IntegrityError, match="cannot be replaced"):
            await connection.execute(
                "INSERT OR REPLACE INTO audit_entries "
                "SELECT sequence, occurred_at, event_type, request_id, session_id, "
                "data_json, previous_hash, entry_hash FROM audit_entries WHERE sequence = 1"
            )
        await connection.rollback()

        assert (await AuditLog(database).verify()).valid is True


@pytest.mark.asyncio
async def test_verifier_detects_a_missing_plan_integrity_trigger(tmp_path: Path) -> None:
    async with Database(tmp_path / "diagnose.sqlite3") as database:
        connection = database._require_connection()
        await connection.execute("DROP TRIGGER execution_plans_no_update")
        await connection.commit()

        verification = await AuditLog(database).verify()

        assert verification.valid is False
        assert any("execution_plans_no_update" in error for error in verification.errors)


@pytest.mark.asyncio
async def test_verifier_reports_malformed_rows_instead_of_raising(tmp_path: Path) -> None:
    path = tmp_path / "diagnose.sqlite3"
    database = Database(path)
    await database.initialize()
    await AuditLog(database).append("test.first", data={"safe": True})
    await AuditLog(database).append("test.second", data={"safe": True})

    connection = database._require_connection()
    await connection.execute("DROP TRIGGER audit_entries_no_update")
    await connection.execute("UPDATE audit_entries SET data_json = '{' WHERE sequence = 1")
    await connection.commit()

    verification = await AuditLog(database).verify()

    assert verification.valid is False
    assert verification.entries_checked == 2
    assert "audit row 1 is malformed" in verification.errors
    await database.close()


@pytest.mark.asyncio
async def test_verifier_survives_unhashable_non_finite_json(tmp_path: Path) -> None:
    path = tmp_path / "diagnose.sqlite3"
    database = Database(path)
    await database.initialize()
    await AuditLog(database).append("test.first", data={"safe": True})

    connection = database._require_connection()
    await connection.execute("DROP TRIGGER audit_entries_no_update")
    await connection.execute("UPDATE audit_entries SET data_json = 'NaN' WHERE sequence = 1")
    await connection.commit()

    verification = await AuditLog(database).verify()

    assert verification.valid is False
    assert verification.errors
    await database.close()
