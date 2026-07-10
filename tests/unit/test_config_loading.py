from pathlib import Path

import pytest

from diagnose.config import (
    CONFIG_DIR_ENV,
    IPC_ENDPOINT_ENV,
    ConfigError,
    default_endpoint_descriptor_path,
    default_runtime_dir,
    default_unix_socket_path,
    load_configuration,
    resolve_config_dir,
    resolve_ipc_endpoint,
)


def test_precedence_is_cli_then_environment_then_default(tmp_path: Path) -> None:
    env_dir = tmp_path / "environment"
    cli_dir = tmp_path / "cli"

    assert resolve_config_dir(cli_dir, environ={CONFIG_DIR_ENV: str(env_dir)}) == cli_dir.resolve()
    assert resolve_config_dir(environ={CONFIG_DIR_ENV: str(env_dir)}) == env_dir.resolve()
    assert resolve_ipc_endpoint("cli", environ={IPC_ENDPOINT_ENV: "environment"}) == "cli"
    assert resolve_ipc_endpoint(environ={IPC_ENDPOINT_ENV: "environment"}) == "environment"


def test_runtime_path_helpers_have_stable_names() -> None:
    assert default_endpoint_descriptor_path() == default_runtime_dir() / "endpoint.json"
    assert default_unix_socket_path() == default_runtime_dir() / "diagnose.sock"


def test_missing_configuration_is_safe_empty_default_deny(tmp_path: Path) -> None:
    configuration = load_configuration(tmp_path)

    assert configuration.targets == ()
    assert configuration.policy_set.policies == {}
    assert configuration.settings.approval_timeout_seconds == 300


def test_loads_valid_target_and_policy_and_hashes_target(tmp_path: Path) -> None:
    (tmp_path / "targets.yaml").write_text(
        """
targets:
  - id: production-api
    displayName: Production API
    type: ssh
    tags: [production]
    connectionRef: ssh:production-api
    policyRef: production-readonly
""",
        encoding="utf-8",
    )
    (tmp_path / "policies.yaml").write_text(
        """
policies:
  production-readonly:
    targets: [production-api]
    defaultDecision: DENY
    tools:
      service_logs:
        decision: ALLOW_WITH_APPROVAL
        maxLines: 100
""",
        encoding="utf-8",
    )

    configuration = load_configuration(tmp_path)

    assert configuration.target("production-api") is not None
    assert configuration.target_version("production-api").startswith("sha256:")


def test_invalid_or_unbound_configuration_blocks_startup(tmp_path: Path) -> None:
    (tmp_path / "targets.yaml").write_text(
        "targets:\n  - id: x\n    displayName: X\n    type: ssh\n"
        "    connectionRef: ssh:x\n    policyRef: missing\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="unknown policy"):
        load_configuration(tmp_path)

    (tmp_path / "targets.yaml").write_text("targets: [", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid or unreadable YAML"):
        load_configuration(tmp_path)
