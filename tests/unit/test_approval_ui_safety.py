from __future__ import annotations

from io import StringIO
from typing import cast

import pytest
from prompt_toolkit import PromptSession
from rich.console import Console

from diagnose.terminal.approval_ui import LineApprovalUI


class AdversarialBackend:
    async def pending_ids(self) -> list[str]:
        return []

    async def render_plan(self, request_id: str) -> str:
        del request_id
        return (
            "\x1b[31m[bold red]APPROVED[/bold red]\x1b[0m"
            "\rDENIED\x1b]8;;https://evil.invalid\x07link\x1b]8;;\x07"
        )

    async def approve(self, request_id: str) -> str:
        del request_id
        return "[green]executed[/green]\x1b]0;forged title\x07"

    async def reject(self, request_id: str, reason: str | None = None) -> str:
        del request_id, reason
        return "rejected"


class UnusedSession:
    async def prompt_async(self, message: str) -> str:
        del message
        raise AssertionError("the show operation must not prompt")


@pytest.mark.anyio
async def test_plan_is_rendered_as_literal_terminal_safe_text() -> None:
    output = StringIO()
    console = Console(file=output, color_system=None, force_terminal=False)
    session = cast(PromptSession[str], UnusedSession())
    ui = LineApprovalUI(AdversarialBackend(), console=console, session=session)

    await ui._show("request-1")

    rendered = output.getvalue()
    assert "[bold red]APPROVED[/bold red]" in rendered
    assert "DENIEDlink" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered
