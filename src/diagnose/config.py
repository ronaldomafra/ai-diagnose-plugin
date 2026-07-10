"""Configuration discovery and strict YAML loading."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import yaml
from platformdirs import user_config_path, user_data_path
from pydantic import Field, JsonValue, ValidationError, field_validator

from diagnose.domain import DomainModel, canonical_sha256
from diagnose.policy import PolicyLimits, PolicySet

CONFIG_DIR_ENV = "DIAGNOSE_CONFIG_DIR"
IPC_ENDPOINT_ENV = "DIAGNOSE_IPC_ENDPOINT"


class ConfigError(ValueError):
    """A startup-blocking configuration error with no secret-bearing context."""


class Settings(DomainModel):
    approval_timeout_seconds: int = Field(default=300, ge=30, le=3600)
    max_output_bytes: int = Field(default=8 * 1024 * 1024, ge=1024, le=8 * 1024 * 1024)
    max_output_lines: int = Field(default=100_000, ge=1, le=1_000_000)
    database_path: Path | None = None
    ipc_endpoint: str | None = Field(default=None, min_length=1, max_length=4096)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    sensitive_fields: list[str] = Field(default_factory=list)
    redaction_patterns: dict[str, str] = Field(default_factory=dict)

    @field_validator("redaction_patterns")
    @classmethod
    def patterns_compile(cls, patterns: dict[str, str]) -> dict[str, str]:
        for label, pattern in patterns.items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"redaction pattern {label!r} is invalid") from exc
        return patterns

    def policy_limits(self) -> PolicyLimits:
        return PolicyLimits(
            timeout_seconds=3600,
            max_output_bytes=self.max_output_bytes,
            max_lines=self.max_output_lines,
            approval_timeout_seconds=self.approval_timeout_seconds,
        )


class TargetConfig(DomainModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", max_length=200)
    display_name: str = Field(min_length=1, max_length=500)
    type: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=100)
    tags: list[str] = Field(default_factory=list)
    connection_ref: str = Field(min_length=1, max_length=1000)
    policy_ref: str = Field(min_length=1, max_length=200)
    engine: str | None = Field(default=None, max_length=100)
    capabilities: list[str] = Field(default_factory=list)
    limits: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("connection_ref")
    @classmethod
    def connection_ref_must_be_indirect(cls, value: str) -> str:
        lowered = value.lower()
        forbidden = ("password=", "pwd=", "token=", "private key", "://")
        if any(marker in lowered for marker in forbidden):
            raise ValueError(
                "connectionRef must name a credential provider, not contain credentials"
            )
        if ":" not in value:
            raise ValueError("connectionRef must use a provider:name reference")
        return value


class TargetSet(DomainModel):
    targets: list[TargetConfig] = Field(default_factory=list)

    @field_validator("targets")
    @classmethod
    def ids_are_unique(cls, targets: list[TargetConfig]) -> list[TargetConfig]:
        identifiers = [target.id for target in targets]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("target IDs must be unique")
        return targets


class Configuration(DomainModel):
    config_dir: Path
    settings: Settings
    target_set: TargetSet
    policy_set: PolicySet

    @property
    def targets(self) -> tuple[TargetConfig, ...]:
        return tuple(self.target_set.targets)

    def target(self, target_id: str) -> TargetConfig | None:
        return next((target for target in self.target_set.targets if target.id == target_id), None)

    def target_version(self, target_id: str) -> str:
        target = self.target(target_id)
        if target is None:
            raise KeyError(target_id)
        return canonical_sha256(target)


def default_config_dir() -> Path:
    return Path(user_config_path("diagnose", appauthor=False))


def default_data_dir() -> Path:
    return Path(user_data_path("diagnose", appauthor=False))


def default_runtime_dir() -> Path:
    """Directory for ephemeral IPC descriptors, tokens, and Unix sockets."""

    return default_data_dir() / "run"


def default_endpoint_descriptor_path() -> Path:
    """Windows loopback endpoint/token descriptor location."""

    return default_runtime_dir() / "endpoint.json"


def default_unix_socket_path() -> Path:
    return default_runtime_dir() / "diagnose.sock"


def resolve_config_dir(
    cli_value: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    env = os.environ if environ is None else environ
    selected = cli_value if cli_value is not None else env.get(CONFIG_DIR_ENV)
    return Path(selected).expanduser().resolve() if selected else default_config_dir().resolve()


def resolve_ipc_endpoint(
    cli_value: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    settings: Settings | None = None,
) -> str | None:
    env = os.environ if environ is None else environ
    if cli_value is not None:
        return cli_value
    if IPC_ENDPOINT_ENV in env:
        return env[IPC_ENDPOINT_ENV]
    return settings.ipc_endpoint if settings is not None else None


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot load {path.name}: invalid or unreadable YAML") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{path.name} must contain a YAML mapping")
    return cast(dict[str, Any], value)


def _unwrap_optional_root(value: dict[str, Any], key: str) -> dict[str, Any]:
    """Allow settings.yaml to use either direct fields or a `settings:` wrapper."""

    if set(value) == {key} and isinstance(value[key], dict):
        return cast(dict[str, Any], value[key])
    return value


def load_configuration(config_dir: str | Path | None = None) -> Configuration:
    """Load all configuration files or safe empty defaults.

    A missing initial configuration is valid and exposes zero targets under the
    global default-deny behavior. A present but malformed file always blocks
    startup.
    """

    directory = resolve_config_dir(config_dir)
    settings_data = _unwrap_optional_root(_read_yaml(directory / "settings.yaml"), "settings")
    targets_data = _read_yaml(directory / "targets.yaml")
    policies_data = _read_yaml(directory / "policies.yaml")
    try:
        settings = Settings.model_validate(settings_data)
        targets = TargetSet.model_validate(targets_data)
        policies = PolicySet.model_validate(policies_data)
    except ValidationError as exc:
        # Validation error locations are safe and useful; input values can contain secrets.
        locations = ", ".join(".".join(map(str, error["loc"])) for error in exc.errors())
        raise ConfigError(f"Configuration validation failed at: {locations}") from exc

    for target in targets.targets:
        policy = policies.policies.get(target.policy_ref)
        if policy is None:
            raise ConfigError(f"Target {target.id!r} references an unknown policy")
        if target.id not in policy.targets:
            raise ConfigError(f"Policy {target.policy_ref!r} is not bound to target {target.id!r}")

    return Configuration(
        config_dir=directory,
        settings=settings,
        target_set=targets,
        policy_set=policies,
    )


def database_path(configuration: Configuration) -> Path:
    configured = configuration.settings.database_path
    if configured:
        expanded = configured.expanduser()
        if not expanded.is_absolute():
            expanded = configuration.config_dir / expanded
        return expanded.resolve()
    return default_data_dir() / "diagnose.sqlite3"


__all__ = [
    "CONFIG_DIR_ENV",
    "IPC_ENDPOINT_ENV",
    "ConfigError",
    "Configuration",
    "Settings",
    "TargetConfig",
    "TargetSet",
    "database_path",
    "default_config_dir",
    "default_data_dir",
    "default_endpoint_descriptor_path",
    "default_runtime_dir",
    "default_unix_socket_path",
    "load_configuration",
    "resolve_config_dir",
    "resolve_ipc_endpoint",
]
