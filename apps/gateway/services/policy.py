"""Declarative policy engine.

Evaluates whether an artifact satisfies organization policy. Fails closed:
if a package has no policy rule, or a rule requirement fails, the policy
check fails and the artifact is not trusted.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from core.models.artifact import Artifact


class PolicyResult:
    def __init__(self, passed: bool, failures: list[str], rule: dict | None = None):
        self.passed = passed
        self.failures = failures
        self.rule = rule or {}

    def __repr__(self) -> str:
        return f"PolicyResult(passed={self.passed}, failures={self.failures})"


class PolicyEngine:
    """Loads a YAML policy file and checks artifacts against it."""

    def __init__(self, policy_file: str | Path):
        self.policy_file = Path(policy_file)
        self.rules = self._load()

    def _load(self) -> list[dict]:
        if not self.policy_file.exists():
            return []
        with open(self.policy_file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data.get("rules", []) or []

    def _rule_for(self, package: str) -> dict | None:
        for rule in self.rules:
            if rule.get("package") == package:
                return rule
        return None

    def evaluate(self, artifact: Artifact) -> PolicyResult:
        failures: list[str] = []
        rule = self._rule_for(artifact.package)

        if rule is None:
            return PolicyResult(False, [f"no policy rule for package '{artifact.package}'"], {})

        # source / registry trust
        allowed_sources = rule.get("source")
        if allowed_sources and artifact.source != allowed_sources:
            failures.append(
                f"source mismatch: expected '{allowed_sources}', got '{artifact.source}' (possible dependency confusion)"
            )

        # publisher trust
        allowed_publisher = rule.get("publisher")
        if allowed_publisher and artifact.publisher != allowed_publisher:
            failures.append(
                f"publisher mismatch: expected '{allowed_publisher}', got '{artifact.publisher}'"
            )

        # dependency confusion: an internal package resolved from an untrusted
        # (public) source is a hard failure even if it has the right name.
        if artifact.source and artifact.source.lower() in ("public", "untrusted"):
            failures.append(
                f"package '{artifact.package}' resolved from untrusted/public source '{artifact.source}'"
            )

        # version pinning
        expected_versions = rule.get("expected_versions")
        if expected_versions and artifact.version not in expected_versions:
            failures.append(
                f"version '{artifact.version}' not in approved versions {expected_versions}"
            )

        # sandbox requirements
        if rule.get("allow_network", False) is False and artifact.policy.get("needs_network"):
            failures.append("artifact requested network but policy requires network denied")

        if rule.get("allow_secrets", False) is False and artifact.policy.get("needs_secrets"):
            failures.append("artifact requested secrets but policy requires secrets denied")

        return PolicyResult(not failures, failures, rule)

    def sandbox_requirements(self, artifact: Artifact) -> dict:
        rule = self._rule_for(artifact.package) or {}
        return {
            "network": "denied" if not rule.get("allow_network", False) else "allowed",
            "secrets": "denied" if not rule.get("allow_secrets", False) else "allowed",
            "filesystem": "restricted",
        }
