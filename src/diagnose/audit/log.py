"""Append-only, hash-chained audit service."""

from __future__ import annotations

import json
import re
from typing import Any, cast

from pydantic import JsonValue

from diagnose.domain import utc_now
from diagnose.persistence import AUDIT_GENESIS_HASH, Database, StoredAuditEntry
from diagnose.sanitization import Sanitizer

from .models import AuditEvent, AuditVerification

GENESIS_HASH = AUDIT_GENESIS_HASH
_REQUIRED_INTEGRITY_TRIGGERS = frozenset(
    {
        "action_events_no_delete",
        "action_events_no_update",
        "audit_entries_no_delete",
        "audit_entries_no_replace",
        "audit_entries_no_update",
        "execution_plans_no_delete",
        "execution_plans_no_update",
        "sanitized_results_no_delete",
        "sanitized_results_no_update",
    }
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def audit_hash_payload(entry: StoredAuditEntry) -> dict[str, Any]:
    """Return exactly the fields committed by an audit entry hash."""

    return entry.hash_payload()


def calculate_audit_hash(entry: StoredAuditEntry) -> str:
    return entry.calculate_hash()


class AuditLog:
    def __init__(self, database: Database, *, sanitizer: Sanitizer | None = None) -> None:
        self.database = database
        self.sanitizer = sanitizer or Sanitizer()

    async def append_event(self, event: AuditEvent) -> StoredAuditEntry:
        """Sanitize and append an event; raw caller data is never persisted."""

        sanitized = self.sanitizer.sanitize(event.data)
        if isinstance(sanitized.data, dict):
            safe_data: dict[str, JsonValue] = sanitized.data
        else:
            safe_data = {"sanitizedOutput": sanitized.data}
        if sanitized.redactions:
            safe_data["_redactions"] = cast(JsonValue, sanitized.redactions)
        if sanitized.truncated:
            safe_data["_truncated"] = True
            safe_data["_originalBytes"] = sanitized.original_bytes
            safe_data["_returnedBytes"] = sanitized.returned_bytes

        return await self.database.append_audit_event(
            event.event_type,
            occurred_at=event.occurred_at,
            request_id=event.request_id,
            session_id=event.session_id,
            data=safe_data,
        )

    async def append(
        self,
        event_type: str,
        *,
        data: dict[str, JsonValue] | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
    ) -> StoredAuditEntry:
        return await self.append_event(
            AuditEvent(
                event_type=event_type,
                occurred_at=utc_now(),
                request_id=request_id,
                session_id=session_id,
                data=data or {},
            )
        )

    async def verify(self) -> AuditVerification:
        rows = await self.database.raw_audit_rows()
        errors: list[str] = []
        expected_previous = GENESIS_HASH
        expected_sequence = 1
        for row_number, row in enumerate(rows, start=1):
            try:
                entry = StoredAuditEntry(
                    sequence=row["sequence"],
                    occurred_at=row["occurred_at"],
                    event_type=row["event_type"],
                    request_id=row["request_id"],
                    session_id=row["session_id"],
                    data=json.loads(row["data_json"]),
                    previous_hash=row["previous_hash"],
                    entry_hash=row["entry_hash"],
                )
            except Exception:
                # The verifier is commonly run precisely because the database
                # may be damaged or externally tampered with. One malformed row
                # must be reported, never abort verification of later rows.
                errors.append(f"audit row {row_number} is malformed")
                raw_hash = row.get("entry_hash")
                if isinstance(raw_hash, str) and _SHA256_RE.fullmatch(raw_hash):
                    expected_previous = raw_hash
                else:
                    expected_previous = "<malformed>"
                raw_sequence = row.get("sequence")
                expected_sequence = (
                    raw_sequence + 1 if isinstance(raw_sequence, int) else expected_sequence + 1
                )
                continue
            if entry.sequence != expected_sequence:
                errors.append(
                    f"sequence discontinuity: expected {expected_sequence}, got {entry.sequence}"
                )
            if entry.previous_hash != expected_previous:
                errors.append(f"entry {entry.sequence} has an invalid previous hash")
            try:
                calculated_hash = calculate_audit_hash(entry)
            except Exception:
                errors.append(f"entry {entry.sequence} content cannot be hashed")
                calculated_hash = None
            if calculated_hash != entry.entry_hash:
                errors.append(f"entry {entry.sequence} hash does not match its content")
            expected_previous = entry.entry_hash
            expected_sequence = entry.sequence + 1

        try:
            integrity = list(await self.database.integrity_check())
            if integrity != ["ok"]:
                errors.append("SQLite integrity_check did not return ok")
        except Exception:
            integrity = ["error"]
            errors.append("SQLite integrity_check could not complete")
        try:
            triggers = await self.database.integrity_trigger_names()
            missing_triggers = sorted(_REQUIRED_INTEGRITY_TRIGGERS - triggers)
            if missing_triggers:
                errors.append("required audit triggers are missing: " + ", ".join(missing_triggers))
        except Exception:
            errors.append("audit trigger verification could not complete")
        return AuditVerification(
            valid=not errors,
            entries_checked=len(rows),
            sqlite_integrity=integrity,
            errors=errors,
        )
