"""Stable MCP tool result schemas."""

from __future__ import annotations

from typing import Any, Self

from pydantic import Field, JsonValue

from diagnose.domain import DomainModel, NormalizedError


class ToolResult(DomainModel):
    """Common structured response with a short compatibility summary."""

    summary: str = Field(min_length=1, max_length=2000)
    data: dict[str, JsonValue] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    error: NormalizedError | None = None

    @classmethod
    def success(
        cls,
        summary: str,
        data: dict[str, Any] | None = None,
        *,
        warnings: list[str] | None = None,
    ) -> Self:
        return cls(summary=summary, data=data or {}, warnings=warnings or [])

    @classmethod
    def failure(cls, summary: str, error: NormalizedError) -> Self:
        return cls(summary=summary, error=error)
