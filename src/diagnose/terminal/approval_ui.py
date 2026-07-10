"""Line-oriented approval interface for a visible terminal."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from prompt_toolkit import PromptSession
from rich.console import Console
from rich.text import Text

from diagnose.sanitization import strip_terminal_sequences


class ApprovalBackend(Protocol):
    """Operations needed by the interactive approval loop."""

    async def pending_ids(self) -> list[str]: ...

    async def render_plan(self, request_id: str) -> str: ...

    async def approve(self, request_id: str) -> str: ...

    async def reject(self, request_id: str, reason: str | None = None) -> str: ...


class LineApprovalUI:
    """Small command loop that never hides the exact plan from the approver."""

    def __init__(
        self,
        backend: ApprovalBackend,
        *,
        console: Console | None = None,
        session: PromptSession[str] | None = None,
    ) -> None:
        self._backend = backend
        self._console = console or Console()
        self._session = session or PromptSession()

    async def run(self) -> None:
        self._print_help()
        while True:
            raw = (await self._session.prompt_async("diagnose> ")).strip()
            if not raw:
                continue
            command, _, remainder = raw.partition(" ")
            command = command.lower()
            argument = remainder.strip()
            if command in {"quit", "exit"}:
                return
            if command in {"help", "?"}:
                self._print_help()
            elif command == "list":
                pending = await self._backend.pending_ids()
                self._print_literal("No pending actions." if not pending else "\n".join(pending))
            elif command in {"show", "details"}:
                await self._with_id(argument, self._show)
            elif command == "approve":
                await self._with_id(argument, self._approve)
            elif command == "reject":
                request_id, _, reason = argument.partition(" ")
                if not request_id:
                    self._console.print("Usage: reject <request-id> [reason]", style="red")
                else:
                    self._print_literal(await self._backend.reject(request_id, reason or None))
            else:
                self._console.print("Unknown command. Type 'help'.", style="red")

    async def _show(self, request_id: str) -> None:
        self._print_literal(await self._backend.render_plan(request_id))

    async def _approve(self, request_id: str) -> None:
        plan = await self._backend.render_plan(request_id)
        self._print_literal(plan)
        confirmation = (
            await self._session.prompt_async("Approve this exact action once? [y/N] ")
        ).strip()
        if confirmation.lower() in {"y", "yes"}:
            self._print_literal(await self._backend.approve(request_id))
        else:
            self._console.print("Approval cancelled locally.")

    async def _with_id(
        self,
        request_id: str,
        operation: Callable[[str], Awaitable[None]],
    ) -> None:
        if not request_id:
            self._console.print("A request id is required.", style="red")
            return
        await operation(request_id)

    def _print_help(self) -> None:
        self._console.print(
            "Commands: list, show <id>, approve <id>, reject <id> [reason], help, quit"
        )

    def _print_literal(self, value: str) -> None:
        """Render backend-controlled text without terminal or Rich interpretation."""

        self._console.print(Text(strip_terminal_sequences(value)))
