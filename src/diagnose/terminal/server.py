"""Command-line entrypoint for the visible Diagnose Terminal Server."""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from diagnose import __version__
from diagnose.audit import AuditLog
from diagnose.config import (
    ConfigError,
    Configuration,
    database_path,
    default_endpoint_descriptor_path,
    default_unix_socket_path,
    load_configuration,
)
from diagnose.domain import DiagnoseError
from diagnose.ipc import endpoint_permissions_are_private
from diagnose.mcp.gateway import IpcGateway
from diagnose.persistence import Database
from diagnose.terminal.approval_ui import LineApprovalUI
from diagnose.terminal.runtime import TerminalRuntime

LOGGER = logging.getLogger(__name__)
CONSOLE = Console()


class _UiBackend:
    def __init__(self, runtime: TerminalRuntime) -> None:
        self.runtime = runtime

    async def pending_ids(self) -> list[str]:
        return await self.runtime.actions.pending_ids()

    async def render_plan(self, request_id: str) -> str:
        return await self.runtime.actions.render_plan(request_id)

    async def approve(self, request_id: str) -> str:
        action = await self.runtime.actions.approve(request_id)
        return f"Action {action.request_id} is {action.status.value}."

    async def reject(self, request_id: str, reason: str | None = None) -> str:
        action = await self.runtime.actions.reject(request_id, reason)
        return f"Action {action.request_id} is {action.status.value}."


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="diagnose-terminal")
    parser.add_argument("--config-dir", help="Override the user configuration directory.")
    parser.add_argument("--endpoint", help="Override the IPC descriptor/socket path.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("start", help="Start the visible approval server.")
    subparsers.add_parser("status", help="Query the running server.")
    subparsers.add_parser("doctor", help="Validate the local installation without changing it.")

    targets = subparsers.add_parser("targets", help="Inspect configured logical targets.")
    target_commands = targets.add_subparsers(dest="targets_command", required=True)
    target_commands.add_parser("list")
    target_describe = target_commands.add_parser("describe")
    target_describe.add_argument("id")
    target_test = target_commands.add_parser("test")
    target_test.add_argument("id")

    actions = subparsers.add_parser("actions", help="Inspect persisted actions.")
    action_commands = actions.add_subparsers(dest="actions_command", required=True)
    action_commands.add_parser("list")
    action_show = action_commands.add_parser("show")
    action_show.add_argument("request_id")

    sessions = subparsers.add_parser("sessions", help="Inspect persisted sessions.")
    session_commands = sessions.add_subparsers(dest="sessions_command", required=True)
    session_commands.add_parser("list")

    audit = subparsers.add_parser("audit", help="Verify the local audit chain.")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    audit_commands.add_parser("verify")
    return parser


async def _start(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        CONSOLE.print(
            "diagnose-terminal start requires a visible interactive terminal.",
            style="red",
        )
        return 3
    runtime = await TerminalRuntime.start(config_dir=args.config_dir, endpoint=args.endpoint)
    endpoint = runtime.endpoint
    CONSOLE.print(f"Diagnose Terminal Server {__version__}")
    CONSOLE.print(f"IPC: {endpoint.transport.value}")
    if endpoint.host is not None:
        CONSOLE.print(f"Endpoint: {endpoint.host}:{endpoint.port}")
    else:
        CONSOLE.print(f"Endpoint: {endpoint.socket_path}")
    CONSOLE.print(f"Targets: {len(runtime.configuration.targets)}")
    CONSOLE.print(f"Policies: {len(runtime.configuration.policy_set.policies)}")
    try:
        await LineApprovalUI(_UiBackend(runtime), console=CONSOLE).run()
    finally:
        await runtime.close()
    return 0


async def _status(args: argparse.Namespace) -> int:
    try:
        response = await IpcGateway(args.endpoint).request("server.info", {})
    except DiagnoseError as exc:
        CONSOLE.print(exc.error.message, style="red")
        return 3
    _print_json(response)
    return 0


def _doctor(args: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, *, required: bool = True) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail, "required": required})

    add("python", sys.version_info >= (3, 12), sys.version.split()[0])
    add("package", True, __version__)
    try:
        configuration = load_configuration(args.config_dir)
        add("configuration", True, str(configuration.config_dir))
    except ConfigError as exc:
        add("configuration", False, str(exc))
        configuration = None
    default_endpoint = (
        default_endpoint_descriptor_path() if os.name == "nt" else default_unix_socket_path()
    )
    endpoint = Path(args.endpoint) if args.endpoint else default_endpoint
    add("ipc endpoint", endpoint.exists(), str(endpoint), required=False)
    if endpoint.exists():
        private_endpoint = endpoint_permissions_are_private(endpoint)
        add(
            "ipc permissions",
            private_endpoint,
            "private to the current user" if private_endpoint else "permissions are too broad",
        )
    for module, label in [
        ("asyncssh", "SSH support"),
        ("psycopg", "PostgreSQL support"),
        ("pyodbc", "SQL Server support"),
        ("asyncmy", "MySQL support"),
    ]:
        add(label, importlib.util.find_spec(module) is not None, module, required=False)
    if configuration is not None:
        path = database_path(configuration)
        if path.exists():
            try:
                uri = f"file:{path.as_posix()}?mode=ro"
                with sqlite3.connect(uri, uri=True) as connection:
                    result = connection.execute("PRAGMA integrity_check").fetchone()
                add("audit database", bool(result and result[0] == "ok"), str(path))
            except sqlite3.Error as exc:
                add("audit database", False, str(exc))
        else:
            add("audit database", True, "not created yet")
    _print_checks(checks)
    return 0 if all(item["ok"] or not item["required"] for item in checks) else 2


async def _offline_database(configuration: Configuration) -> Database:
    database = Database(database_path(configuration))
    await database.initialize()
    return database


async def _run_command(args: argparse.Namespace) -> int:
    if args.command == "start":
        return await _start(args)
    if args.command == "status":
        return await _status(args)
    if args.command == "doctor":
        return _doctor(args)
    configuration = load_configuration(args.config_dir)
    if args.command == "targets":
        if args.targets_command == "list":
            _print_json({"targets": [_safe_target(target) for target in configuration.targets]})
            return 0
        target = configuration.target(args.id)
        if target is None:
            CONSOLE.print("Target not found.", style="red")
            return 2
        if args.targets_command == "describe":
            _print_json({"target": _safe_target(target)})
            return 0
        CONSOLE.print("Target connection tests are not available in milestone M0.", style="yellow")
        return 3

    database = await _offline_database(configuration)
    try:
        if args.command == "actions":
            if args.actions_command == "list":
                actions = await database.list_actions(limit=100)
                _print_json({"actions": [_wire(action) for action in actions]})
                return 0
            action = await database.get_action(args.request_id)
            if action is None:
                CONSOLE.print("Action not found.", style="red")
                return 2
            plan = await database.load_execution_plan(args.request_id)
            result = await database.get_result(args.request_id)
            _print_json(
                {
                    "action": _wire(action),
                    "plan": _wire(plan) if plan is not None else None,
                    "result": _wire(result) if result is not None else None,
                }
            )
            return 0
        if args.command == "sessions":
            sessions = await database.list_sessions()
            _print_json({"sessions": [_wire(session) for session in sessions]})
            return 0
        verification = await AuditLog(database).verify()
        _print_json(_wire(verification))
        return 0 if verification.valid else 2
    finally:
        await database.close()


def _wire(value: Any) -> Any:
    return value.model_dump(mode="json", by_alias=True) if hasattr(value, "model_dump") else value


def _safe_target(target: Any) -> dict[str, Any]:
    return {
        "id": target.id,
        "displayName": target.display_name,
        "type": target.type,
        "tags": target.tags,
        "engine": target.engine,
        "capabilities": target.capabilities,
        "limits": target.limits,
    }


def _print_json(value: Any) -> None:
    CONSOLE.print_json(json.dumps(value, ensure_ascii=False, default=str))


def _print_checks(checks: list[dict[str, Any]]) -> None:
    table = Table("Check", "Status", "Detail")
    for item in checks:
        status = "OK" if item["ok"] else ("OPTIONAL" if not item["required"] else "FAILED")
        table.add_row(str(item["name"]), status, str(item["detail"]))
    CONSOLE.print(table)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        exit_code = asyncio.run(_run_command(_parser().parse_args()))
    except ConfigError as exc:
        CONSOLE.print(str(exc), style="red")
        exit_code = 2
    except KeyboardInterrupt:
        exit_code = 130
    except Exception:
        LOGGER.exception("Terminal command failed")
        exit_code = 1
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
