from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.asyncio
async def test_mcp_stdio_initializes_and_returns_structured_offline_result(
    tmp_path: Path,
) -> None:
    missing_endpoint = tmp_path / ("missing.json" if os.name == "nt" else "missing.sock")
    environment = os.environ.copy()
    environment["DIAGNOSE_IPC_ENDPOINT"] = str(missing_endpoint)
    stderr_path = tmp_path / "mcp-stderr.log"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "diagnose.mcp.server"],
        cwd=PROJECT_ROOT,
        env=environment,
    )

    with stderr_path.open("w", encoding="utf-8") as stderr:
        async with stdio_client(parameters, errlog=stderr) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                initialized = await session.initialize()
                assert initialized.serverInfo.name == "diagnose"

                catalog = await session.list_tools()
                assert [tool.name for tool in catalog.tools] == [
                    "server_info",
                    "capabilities_list",
                    "target_list",
                    "target_describe",
                    "diagnosis_session_create",
                    "diagnosis_session_status",
                    "diagnosis_session_close",
                    "action_status",
                    "action_result",
                    "action_cancel",
                    "action_history",
                ]

                result = await session.call_tool("server_info", {})
                assert result.isError is False
                assert result.structuredContent is not None
                assert result.structuredContent["error"]["code"] == "TERMINAL_SERVER_OFFLINE"
                assert result.structuredContent["error"]["retryable"] is True
                assert "diagnose-terminal start" in result.structuredContent["error"]["nextStep"]

    assert stderr_path.read_text(encoding="utf-8") == ""
