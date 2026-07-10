from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from diagnose.domain import ErrorCode
from diagnose.mcp.gateway import OfflineGateway, set_gateway_factory
from diagnose.mcp.server import mcp, server_info, target_describe


class StubGateway:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def request(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((message_type, payload))
        return {"summary": "stub response", "value": 42}


@pytest.fixture(autouse=True)
def reset_gateway() -> None:
    set_gateway_factory(OfflineGateway)


def test_m0_tool_catalog_and_schemas_are_static_and_strict() -> None:
    tools = mcp._tool_manager.list_tools()

    assert [tool.name for tool in tools] == [
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
    assert all(tool.parameters["additionalProperties"] is False for tool in tools)
    assert all(
        tool.output_schema is not None and tool.output_schema["additionalProperties"] is False
        for tool in tools
    )


@pytest.mark.asyncio
async def test_offline_terminal_is_a_structured_result() -> None:
    result = await server_info()

    assert result.error is not None
    assert result.error.code is ErrorCode.TERMINAL_SERVER_OFFLINE
    assert "diagnose-terminal start" in (result.error.next_step or "")


@pytest.mark.asyncio
async def test_tool_forwards_wire_names_to_gateway() -> None:
    gateway = StubGateway()
    set_gateway_factory(lambda: gateway)

    result = await target_describe("local-test")

    assert result.summary == "stub response"
    assert result.data == {"value": 42}
    assert gateway.calls == [("targets.describe", {"targetId": "local-test"})]


@pytest.mark.asyncio
async def test_fastmcp_argument_model_rejects_unknown_fields() -> None:
    tool = next(tool for tool in mcp._tool_manager.list_tools() if tool.name == "server_info")

    with pytest.raises(ValidationError, match="extra_forbidden"):
        await tool.fn_metadata.call_fn_with_arg_validation(
            tool.fn,
            tool.is_async,
            {"unexpected": True},
            None,
        )
