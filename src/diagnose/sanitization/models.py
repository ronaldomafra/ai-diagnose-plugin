"""Sanitization result contracts."""

from __future__ import annotations

from pydantic import Field, JsonValue

from diagnose.domain import DomainModel


class SanitizedValue(DomainModel):
    data: JsonValue
    redactions: list[str] = Field(default_factory=list)
    truncated: bool = False
    original_bytes: int = Field(ge=0)
    returned_bytes: int = Field(ge=0)
