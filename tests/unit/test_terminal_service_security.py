from __future__ import annotations

from diagnose.config import TargetConfig
from diagnose.sanitization import Sanitizer
from diagnose.terminal.service import _safe_target


def test_target_metadata_is_sanitized_before_it_can_reach_mcp() -> None:
    secret = "target-secret"
    target = TargetConfig(
        id="safe-target",
        display_name=f"API token={secret}",
        type="fake",
        connection_ref="fake:target",
        policy_ref="safe-policy",
        capabilities=["fake_probe"],
        limits={"password": secret, "timeoutSeconds": 5},
    )

    safe = _safe_target(target, Sanitizer())

    assert secret not in str(safe)
    assert safe["displayName"] == "API token=[REDACTED]"
    assert safe["limits"] == {"password": "[REDACTED]", "timeoutSeconds": 5}
