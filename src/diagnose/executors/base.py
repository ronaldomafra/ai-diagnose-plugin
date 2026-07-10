"""Executor contracts kept independent from transport and MCP details."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from diagnose.domain import ExecutionPlan


class ExecutionOutput(BaseModel):
    """Raw executor output before mandatory sanitization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    data: Mapping[str, Any] = Field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    exit_code: int | None = None


class Executor(Protocol):
    """A concrete operation executor."""

    @property
    def name(self) -> str: ...

    async def execute(
        self,
        plan: ExecutionPlan,
        cancel_event: asyncio.Event,
    ) -> ExecutionOutput: ...
