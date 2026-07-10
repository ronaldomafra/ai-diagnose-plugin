"""Shared Pydantic conventions for public Diagnose contracts."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


def to_camel(value: str) -> str:
    """Convert a snake_case Python name to the JSON camelCase convention."""

    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class DomainModel(BaseModel):
    """Base for wire/storage models.

    Models accept both their Python names and wire aliases so internal code can
    stay idiomatic while every serialized public contract remains camelCase.
    Unknown input is rejected: silently accepting an agent-provided field can
    turn a validation mistake into a security policy bypass.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
    )


class FrozenDomainModel(DomainModel):
    """Immutable variant used for plans and other approval artifacts."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )
