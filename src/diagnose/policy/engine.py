"""Fail-closed policy selection and versioning."""

from __future__ import annotations

from diagnose.domain import PolicyDecision, canonical_sha256

from .models import PolicyEvaluation, PolicyLimits, PolicySet, merge_limits


class PolicyEngine:
    def __init__(
        self,
        policy_set: PolicySet,
        *,
        global_limits: PolicyLimits | None = None,
    ) -> None:
        self.policy_set = policy_set
        self.global_limits = global_limits or PolicyLimits()
        self.version = canonical_sha256(
            {"policies": policy_set, "globalLimits": self.global_limits}
        )

    def evaluate(self, *, policy_ref: str | None, target_id: str, tool: str) -> PolicyEvaluation:
        """Return a decision; every missing or inconsistent binding is DENY."""

        if not policy_ref:
            return self._deny("Target has no policy binding.")
        policy = self.policy_set.policies.get(policy_ref)
        if policy is None:
            return self._deny("Referenced policy does not exist.", policy_ref=policy_ref)
        if target_id not in policy.targets:
            return self._deny(
                "Policy is not bound to this target.",
                policy_ref=policy_ref,
                policy_version=self._policy_version(policy_ref),
            )

        rule = policy.tools.get(tool)
        decision = rule.decision if rule is not None else policy.default_decision
        policy_version = self._policy_version(policy_ref)
        if rule is None or decision is not PolicyDecision.ALLOW_WITH_APPROVAL:
            return self._deny(
                "Tool is denied by policy.",
                policy_ref=policy_ref,
                policy_version=policy_version,
            )

        return PolicyEvaluation(
            decision=PolicyDecision.ALLOW_WITH_APPROVAL,
            policy_ref=policy_ref,
            policy_version=policy_version,
            limits=merge_limits(global_limits=self.global_limits, tool=rule),
            allowed_services=tuple(rule.allowed_services),
            allowed_executables=tuple(rule.allowed_executables),
            constraints=rule.constraints,
            reason="Tool is allowed with one-time local approval.",
        )

    def _policy_version(self, policy_ref: str) -> str:
        return canonical_sha256(
            {
                "policyRef": policy_ref,
                "policy": self.policy_set.policies[policy_ref],
                "globalLimits": self.global_limits,
            }
        )

    def _deny(
        self,
        reason: str,
        *,
        policy_ref: str | None = None,
        policy_version: str | None = None,
    ) -> PolicyEvaluation:
        return PolicyEvaluation(
            decision=PolicyDecision.DENY,
            policy_ref=policy_ref,
            policy_version=policy_version or self.version,
            limits=self.global_limits,
            reason=reason,
        )
