"""STDIO MCP server exposing M0 control and session tools."""

from __future__ import annotations

import logging
import sys
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from diagnose.domain import DiagnoseError, ErrorCode, NormalizedError
from diagnose.mcp.gateway import get_gateway
from diagnose.mcp.schemas import ToolResult

LOGGER = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
LOCAL_MUTATION = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
LOCAL_IDEMPOTENT_MUTATION = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

mcp = FastMCP(
    "diagnose",
    instructions="Human-approved diagnostic control and session tools.",
    log_level="WARNING",
)


async def _call(message_type: str, payload: dict[str, Any], summary: str) -> ToolResult:
    try:
        response = await get_gateway().request(message_type, payload)
        returned_summary = response.pop("summary", summary)
        warnings = response.pop("warnings", [])
        return ToolResult.success(str(returned_summary), response, warnings=list(warnings))
    except DiagnoseError as exc:
        return ToolResult.failure(exc.error.message, exc.error)
    except (ConnectionError, FileNotFoundError, OSError):
        error = NormalizedError(
            code=ErrorCode.TERMINAL_SERVER_OFFLINE,
            message="The Diagnose Terminal Server is offline.",
            next_step="Start it in a visible terminal with 'diagnose-terminal start'.",
            retryable=True,
        )
        return ToolResult.failure(error.message, error)
    except Exception:
        LOGGER.exception("Unexpected terminal gateway failure")
        error = NormalizedError(
            code=ErrorCode.INTERNAL_ERROR,
            message="The diagnostic request failed internally.",
            next_step="Inspect Diagnose logs in the local terminal.",
        )
        return ToolResult.failure(error.message, error)


@mcp.tool(
    description="Get the local Terminal Server version, protocol, and connection state.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def server_info() -> ToolResult:
    return await _call("server.info", {}, "Terminal Server information retrieved.")


@mcp.tool(
    description="List global and target-specific diagnostic capabilities.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def capabilities_list(
    targetId: Annotated[str, Field(min_length=1, max_length=200)] | None = None,
) -> ToolResult:
    payload = {"targetId": targetId} if targetId is not None else {}
    return await _call("capabilities.list", payload, "Capabilities retrieved.")


@mcp.tool(
    description="List configured logical targets without exposing credentials.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def target_list(
    targetType: str | None = None,
    tags: list[str] | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 100,
) -> ToolResult:
    return await _call(
        "targets.list",
        {"targetType": targetType, "tags": tags or [], "cursor": cursor, "limit": limit},
        "Targets retrieved.",
    )


@mcp.tool(
    description="Describe one logical target using non-sensitive metadata.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def target_describe(
    targetId: Annotated[str, Field(min_length=1, max_length=200)],
) -> ToolResult:
    return await _call("targets.describe", {"targetId": targetId}, "Target retrieved.")


@mcp.tool(
    description="Create a persisted diagnosis session.",
    annotations=LOCAL_MUTATION,
    structured_output=True,
)
async def diagnosis_session_create(
    responseLevel: Literal["junior", "pleno", "senior", "auto"] = "pleno",
    mode: Literal["manual", "connected"] = "connected",
) -> ToolResult:
    return await _call(
        "sessions.create",
        {"responseLevel": responseLevel, "mode": mode},
        "Diagnosis session created.",
    )


@mcp.tool(
    description="Get the state and metadata of a diagnosis session.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def diagnosis_session_status(
    sessionId: Annotated[str, Field(min_length=5, max_length=200)],
) -> ToolResult:
    return await _call("sessions.get", {"sessionId": sessionId}, "Session retrieved.")


@mcp.tool(
    description="Close a diagnosis session without deleting its audit history.",
    annotations=LOCAL_IDEMPOTENT_MUTATION,
    structured_output=True,
)
async def diagnosis_session_close(
    sessionId: Annotated[str, Field(min_length=5, max_length=200)],
    outcome: Literal["BLOCKED", "RESOLVED", "INTERRUPTED", "CLOSED"] = "CLOSED",
) -> ToolResult:
    return await _call(
        "sessions.close",
        {"sessionId": sessionId, "outcome": outcome},
        "Session closed.",
    )


@mcp.tool(
    description="Get the current state of a human-approved action.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def action_status(
    requestId: Annotated[str, Field(min_length=5, max_length=200)],
) -> ToolResult:
    return await _call("action.status", {"requestId": requestId}, "Action status retrieved.")


@mcp.tool(
    description="Get the sanitized result of a completed action.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def action_result(
    requestId: Annotated[str, Field(min_length=5, max_length=200)],
) -> ToolResult:
    return await _call("action.result", {"requestId": requestId}, "Action result retrieved.")


@mcp.tool(
    description="Request cancellation of a pending or executing action.",
    annotations=LOCAL_IDEMPOTENT_MUTATION,
    structured_output=True,
)
async def action_cancel(
    requestId: Annotated[str, Field(min_length=5, max_length=200)],
    reason: Annotated[str, Field(min_length=1, max_length=1000)] | None = None,
) -> ToolResult:
    return await _call(
        "action.cancel",
        {"requestId": requestId, "reason": reason},
        "Action cancellation requested.",
    )


@mcp.tool(
    description="List sanitized action history for a diagnosis session.",
    annotations=READ_ONLY,
    structured_output=True,
)
async def action_history(
    sessionId: Annotated[str, Field(min_length=5, max_length=200)],
    cursor: str | None = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 100,
) -> ToolResult:
    return await _call(
        "action.history",
        {"sessionId": sessionId, "cursor": cursor, "limit": limit},
        "Action history retrieved.",
    )


def _harden_generated_input_models() -> None:
    """Make FastMCP reject unknown arguments instead of silently ignoring them."""
    for tool in mcp._tool_manager.list_tools():
        tool.parameters["additionalProperties"] = False
        tool.fn_metadata.arg_model.model_config["extra"] = "forbid"
        tool.fn_metadata.arg_model.model_rebuild(force=True)


_harden_generated_input_models()


def main() -> None:
    """Run the adapter without contaminating the STDIO protocol stream."""
    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
