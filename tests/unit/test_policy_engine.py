import pytest
from pydantic import ValidationError

from diagnose.domain import PolicyDecision
from diagnose.policy import (
    PolicyDefinition,
    PolicyEngine,
    PolicyLimits,
    PolicySet,
    ToolPolicy,
)


def make_engine() -> PolicyEngine:
    return PolicyEngine(
        PolicySet(
            policies={
                "readonly": PolicyDefinition(
                    targets=["production-api"],
                    tools={
                        "service_logs": ToolPolicy(
                            decision=PolicyDecision.ALLOW_WITH_APPROVAL,
                            max_output_bytes=512_000,
                            timeout_seconds=30,
                        )
                    },
                )
            }
        ),
        global_limits=PolicyLimits(max_output_bytes=256_000, timeout_seconds=20),
    )


def test_policy_engine_is_default_deny() -> None:
    engine = make_engine()

    cases = [
        (None, "production-api", "service_logs"),
        ("missing", "production-api", "service_logs"),
        ("readonly", "other", "service_logs"),
        ("readonly", "production-api", "unknown"),
    ]
    for policy_ref, target_id, tool in cases:
        evaluation = engine.evaluate(policy_ref=policy_ref, target_id=target_id, tool=tool)
        assert evaluation.decision is PolicyDecision.DENY


def test_matching_rule_requires_approval_and_never_widens_global_limits() -> None:
    evaluation = make_engine().evaluate(
        policy_ref="readonly", target_id="production-api", tool="service_logs"
    )

    assert evaluation.allowed
    assert evaluation.decision is PolicyDecision.ALLOW_WITH_APPROVAL
    assert evaluation.limits.timeout_seconds == 20
    assert evaluation.limits.max_output_bytes == 256_000
    assert evaluation.policy_version.startswith("sha256:")


def test_allow_automatic_is_rejected_as_invalid_v1_policy() -> None:
    with pytest.raises(ValidationError, match="reserved"):
        ToolPolicy(decision=PolicyDecision.ALLOW_AUTOMATIC)
