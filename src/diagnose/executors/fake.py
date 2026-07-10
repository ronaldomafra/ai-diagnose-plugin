"""Deterministic executor used only through dependency injection in tests."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import suppress
from typing import Any

from diagnose.domain import ExecutionPlan
from diagnose.executors.base import ExecutionOutput


class FakeExecutionError(RuntimeError):
    """Raised when a fake execution is configured to fail."""


class FakeExecutor:
    """Return configured data while honoring cancellation."""

    name = "fake"

    def __init__(
        self,
        data: Mapping[str, Any] | None = None,
        *,
        delay_seconds: float = 0.0,
        error: str | None = None,
    ) -> None:
        self._data = dict(data or {"ok": True})
        self._delay_seconds = delay_seconds
        self._error = error
        self.calls = 0

    async def execute(self, plan: ExecutionPlan, cancel_event: asyncio.Event) -> ExecutionOutput:
        del plan
        self.calls += 1
        if self._delay_seconds:
            with suppress(TimeoutError):
                await asyncio.wait_for(cancel_event.wait(), timeout=self._delay_seconds)
        if cancel_event.is_set():
            raise asyncio.CancelledError
        if self._error is not None:
            raise FakeExecutionError(self._error)
        return ExecutionOutput(data=self._data)
