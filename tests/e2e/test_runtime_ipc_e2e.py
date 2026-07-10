from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from diagnose.domain import DiagnoseError, ErrorCode
from diagnose.mcp.gateway import IpcGateway
from diagnose.terminal.runtime import TerminalRuntime


@pytest.mark.asyncio
async def test_terminal_runtime_serves_persisted_sessions_over_real_ipc(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    database_path = tmp_path / "data" / "diagnose.sqlite3"
    (config_dir / "settings.yaml").write_text(
        json.dumps({"database_path": str(database_path)}),
        encoding="utf-8",
    )
    endpoint_path = tmp_path / ("endpoint.json" if os.name == "nt" else "diagnose.sock")

    runtime = await TerminalRuntime.start(config_dir=config_dir, endpoint=endpoint_path)
    try:
        gateway = IpcGateway(endpoint_path)

        info = await gateway.request("server.info", {})
        assert info["terminalOnline"] is True
        assert info["targetCount"] == 0
        assert info["policyCount"] == 0
        assert "authToken" not in info["endpoint"]

        created = await gateway.request(
            "sessions.create",
            {"responseLevel": "senior", "mode": "connected"},
        )
        session = created["session"]
        assert isinstance(session, dict)
        session_id = session["sessionId"]
        assert isinstance(session_id, str)
        assert session["state"] == "COLLECTING"
        assert session["metadata"] == {"responseLevel": "senior", "mode": "connected"}

        fetched = await gateway.request("sessions.get", {"sessionId": session_id})
        assert fetched["session"] == session

        secret_cursor = "password=cursor-secret"
        with pytest.raises(DiagnoseError) as captured:
            await gateway.request("targets.list", {"cursor": secret_cursor, "limit": 10})
        assert captured.value.error.code is ErrorCode.INVALID_ARGUMENT
        assert secret_cursor not in captured.value.error.message

        closed = await gateway.request(
            "sessions.close",
            {"sessionId": session_id, "outcome": "RESOLVED"},
        )
        assert closed["session"]["state"] == "CLOSED"
        assert (await runtime.audit.verify()).valid is True
        assert endpoint_path.exists()
        assert database_path.exists()
    finally:
        await runtime.close()

    assert not endpoint_path.exists()
