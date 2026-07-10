"""Application-level IPC dispatcher for the visible Terminal Server."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, cast

from pydantic import JsonValue, ValidationError

from diagnose import __version__
from diagnose.approval import ActionService, ActionSubmission
from diagnose.audit import AuditLog
from diagnose.config import Configuration
from diagnose.domain import (
    DiagnoseError,
    DiagnosisSession,
    ErrorCode,
    NormalizedError,
)
from diagnose.ipc import PROTOCOL_VERSION, EndpointDescriptor, Envelope
from diagnose.persistence import Database
from diagnose.sanitization import Sanitizer

LOGGER = logging.getLogger(__name__)

_M0_CONTROL_CAPABILITIES = [
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


class TerminalService:
    """Translate authenticated IPC messages into domain operations."""

    def __init__(
        self,
        database: Database,
        configuration_provider: Callable[[], Configuration],
        action_service: ActionService,
        audit_log: AuditLog,
        *,
        available_capabilities: set[str] | None = None,
    ) -> None:
        self.database = database
        self._configuration_provider = configuration_provider
        self.actions = action_service
        self.audit = audit_log
        self.available_capabilities = available_capabilities or set()
        self.endpoint: EndpointDescriptor | None = None

    async def handle(self, request: Envelope) -> Envelope:
        try:
            payload = await self._dispatch(request.message_type, dict(request.payload))
        except DiagnoseError as exc:
            payload = _error_payload(exc.error)
        except ValidationError as exc:
            locations = ", ".join(".".join(map(str, item["loc"])) for item in exc.errors())
            payload = _error_payload(
                NormalizedError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message=f"Request validation failed at: {locations}",
                    next_step="Correct the tool arguments and retry.",
                )
            )
        except (KeyError, ValueError):
            payload = _error_payload(
                NormalizedError(
                    code=ErrorCode.INVALID_ARGUMENT,
                    message="Request arguments are invalid.",
                    next_step="Review the request identifiers and arguments.",
                )
            )
        except Exception:
            LOGGER.exception("Unhandled Terminal Server request: %s", request.message_type)
            payload = _error_payload(
                NormalizedError(
                    code=ErrorCode.INTERNAL_ERROR,
                    message="The Terminal Server failed internally.",
                    next_step="Inspect the visible terminal logs.",
                )
            )
        return Envelope(
            message_type=f"{request.message_type}.result",
            correlation_id=request.correlation_id,
            payload=payload,
        )

    async def _dispatch(self, message_type: str, payload: dict[str, Any]) -> dict[str, JsonValue]:
        if message_type in {"server.ping", "server.info"}:
            return self._server_info()
        if message_type == "capabilities.list":
            return self._capabilities(payload)
        if message_type == "targets.list":
            return self._targets(payload)
        if message_type == "targets.describe":
            return self._target(payload)
        if message_type == "sessions.create":
            return await self._create_session(payload)
        if message_type == "sessions.get":
            return await self._get_session(payload)
        if message_type == "sessions.close":
            return await self._close_session(payload)
        if message_type == "action.submit":
            action = await self.actions.submit(ActionSubmission.model_validate(payload))
            return {
                "summary": "Action submitted for local policy evaluation.",
                "action": _wire(action),
            }
        if message_type == "action.status":
            action = await self.actions.status(_required_string(payload, "requestId"))
            return {"summary": "Action status retrieved.", "action": _wire(action)}
        if message_type == "action.result":
            request_id = _required_string(payload, "requestId")
            action = await self.actions.status(request_id)
            result = await self.actions.result(request_id)
            return {
                "summary": "Action result retrieved." if result else "Action result is not ready.",
                "available": result is not None,
                "status": action.status.value,
                "result": _wire(result) if result is not None else None,
            }
        if message_type == "action.cancel":
            action = await self.actions.cancel(
                _required_string(payload, "requestId"),
                _optional_string(payload, "reason"),
            )
            return {"summary": "Action cancellation processed.", "action": _wire(action)}
        if message_type == "action.history":
            limit = _bounded_limit(payload.get("limit", 100))
            actions = await self.actions.history(
                _required_string(payload, "sessionId"),
                limit=limit,
            )
            return {
                "summary": "Action history retrieved.",
                "actions": [_wire(action) for action in actions],
                "nextCursor": None,
            }
        raise DiagnoseError(
            ErrorCode.INVALID_ARGUMENT,
            "The IPC message type is not supported.",
            next_step="Use a tool advertised by the Diagnose MCP server.",
        )

    def _server_info(self) -> dict[str, JsonValue]:
        configuration = self._configuration_provider()
        endpoint = _public_endpoint(self.endpoint) if self.endpoint is not None else None
        return {
            "summary": "Terminal Server is online.",
            "serverVersion": __version__,
            "protocolVersion": PROTOCOL_VERSION,
            "terminalOnline": True,
            "endpoint": endpoint,
            "targetCount": len(configuration.targets),
            "policyCount": len(configuration.policy_set.policies),
        }

    def _capabilities(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        configuration = self._configuration_provider()
        selected = payload.get("targetId")
        targets: dict[str, JsonValue] = {}
        for target in configuration.targets:
            if selected is not None and target.id != selected:
                continue
            targets[target.id] = cast(
                JsonValue,
                [
                    capability
                    for capability in target.capabilities
                    if capability in self.available_capabilities
                ],
            )
        if selected is not None and selected not in targets:
            raise DiagnoseError(ErrorCode.TARGET_NOT_FOUND, "The requested target does not exist.")
        return {
            "summary": "Capabilities retrieved.",
            "globalCapabilities": cast(JsonValue, _M0_CONTROL_CAPABILITIES),
            "targets": targets,
        }

    def _targets(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        configuration = self._configuration_provider()
        target_type = payload.get("targetType")
        tags = set(payload.get("tags") or [])
        limit = _bounded_limit(payload.get("limit", 100))
        start = _cursor_offset(payload.get("cursor"))
        selected = [
            target
            for target in configuration.targets
            if (target_type is None or target.type == target_type)
            and (not tags or tags.issubset(target.tags))
        ]
        page = selected[start : start + limit]
        next_cursor = str(start + limit) if start + limit < len(selected) else None
        return {
            "summary": "Targets retrieved.",
            "targets": [_safe_target(target, self.actions.sanitizer) for target in page],
            "nextCursor": next_cursor,
        }

    def _target(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        target_id = _required_string(payload, "targetId")
        target = self._configuration_provider().target(target_id)
        if target is None:
            raise DiagnoseError(ErrorCode.TARGET_NOT_FOUND, "The requested target does not exist.")
        return {
            "summary": "Target retrieved.",
            "target": _safe_target(target, self.actions.sanitizer),
        }

    async def _create_session(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        response_level = str(payload.get("responseLevel", "pleno"))
        mode = str(payload.get("mode", "connected"))
        if response_level not in {"junior", "pleno", "senior", "auto"}:
            raise ValueError("responseLevel must be junior, pleno, senior, or auto")
        if mode not in {"manual", "connected"}:
            raise ValueError("mode must be manual or connected")
        session = await self.database.create_session(
            DiagnosisSession.create(metadata={"responseLevel": response_level, "mode": mode}),
            audit_event_type="session.created",
            audit_data={"responseLevel": response_level, "mode": mode},
        )
        return {"summary": "Diagnosis session created.", "session": _wire(session)}

    async def _get_session(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        session_id = _required_string(payload, "sessionId")
        session = await self.database.get_session(session_id)
        if session is None:
            raise DiagnoseError(ErrorCode.INVALID_ARGUMENT, "The diagnosis session does not exist.")
        return {"summary": "Diagnosis session retrieved.", "session": _wire(session)}

    async def _close_session(self, payload: dict[str, Any]) -> dict[str, JsonValue]:
        session_id = _required_string(payload, "sessionId")
        outcome = str(payload.get("outcome", "CLOSED"))
        if outcome not in {"BLOCKED", "RESOLVED", "INTERRUPTED", "CLOSED"}:
            raise ValueError("outcome must be BLOCKED, RESOLVED, INTERRUPTED, or CLOSED")
        session = await self.database.close_session(
            session_id,
            audit_event_type="session.closed",
            audit_data={"outcome": outcome},
        )
        return {"summary": "Diagnosis session closed.", "session": _wire(session)}


def _wire(value: Any) -> JsonValue:
    if hasattr(value, "model_dump"):
        return cast(JsonValue, value.model_dump(mode="json", by_alias=True))
    return cast(JsonValue, value)


def _safe_target(target: Any, sanitizer: Sanitizer | None = None) -> dict[str, JsonValue]:
    metadata: dict[str, JsonValue] = {
        "id": target.id,
        "displayName": target.display_name,
        "type": target.type,
        "tags": target.tags,
        "engine": target.engine,
        "capabilities": target.capabilities,
        "limits": target.limits,
    }
    if sanitizer is None:
        return metadata
    safe = sanitizer.sanitize(metadata)
    return (
        safe.data
        if isinstance(safe.data, dict)
        else {
            "id": target.id,
            "displayName": "[REDACTED]",
            "type": target.type,
            "tags": [],
            "engine": target.engine,
            "capabilities": [],
            "limits": {},
        }
    )


def _public_endpoint(endpoint: EndpointDescriptor) -> dict[str, JsonValue]:
    """Return connection metadata without ever returning the TCP authentication token."""
    return {
        "protocolVersion": endpoint.protocol_version,
        "transport": endpoint.transport.value,
        "host": endpoint.host,
        "port": endpoint.port,
        "socketPath": endpoint.socket_path,
        "serverPid": endpoint.server_pid,
        "startedAt": endpoint.started_at.isoformat(),
    }


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} is required")
    return value


def _optional_string(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _bounded_limit(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100:
        raise ValueError("limit must be an integer from 1 through 100")
    return value


def _cursor_offset(value: Any) -> int:
    if value is None:
        return 0
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValueError("cursor is invalid")
    offset = int(value)
    if offset > 1_000_000:
        raise ValueError("cursor is invalid")
    return offset


def _error_payload(error: NormalizedError) -> dict[str, JsonValue]:
    return {
        "summary": error.message,
        "error": error.model_dump(mode="json", by_alias=True),
    }
