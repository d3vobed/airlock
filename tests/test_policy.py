"""Policy engine tests.

Default policy rules (core/policies/default.yaml):
  - @naijapay/payment-sdk   source=internal-approved-registry publisher=naijapay
                            versions pinned to ['2.1.0']
  - @naijapay/loyalty-sdk   source=internal-approved-registry publisher=naijapay
"""
from __future__ import annotations

from core.models.artifact import Artifact
from apps.gateway.config import settings
from apps.gateway.services.policy import PolicyEngine

policy = PolicyEngine(settings.policy_file)


def _artifact(package: str, source: str, publisher: str | None, version: str = "1.0.0") -> Artifact:
    return Artifact(
        package=package,
        version=version,
        source=source,
        publisher=publisher,
        digest="x" * 64,
    )


def test_approved_package_allowed():
    r = policy.evaluate(_artifact("@naijapay/payment-sdk", "internal-approved-registry", "naijapay", "2.1.0"))
    assert r.passed is True
    assert r.failures == []


def test_unapproved_source_rejected():
    r = policy.evaluate(_artifact("@naijapay/payment-sdk", "public", "naijapay", "2.1.0"))
    assert r.passed is False
    assert any("source mismatch" in f or "untrusted" in f for f in r.failures)


def test_publisher_mismatch_rejected():
    r = policy.evaluate(_artifact("@naijapay/payment-sdk", "internal-approved-registry", "mallory", "2.1.0"))
    assert r.passed is False
    assert any("publisher mismatch" in f for f in r.failures)


def test_dependency_confusion_rejected():
    r = policy.evaluate(_artifact("@naijapay/payment-sdk", "public", "attacker", "9.9.9"))
    assert r.passed is False
    assert any("untrusted/public source" in f for f in r.failures)


def test_unknown_package_rejected_fails_closed():
    r = policy.evaluate(_artifact("totally-unknown-pkg", "internal-approved-registry", "someone"))
    assert r.passed is False
    assert any("no policy rule" in f for f in r.failures)


def test_version_pinning_enforced():
    r = policy.evaluate(_artifact("@naijapay/payment-sdk", "internal-approved-registry", "naijapay", "99.0.0"))
    assert r.passed is False
    assert any("not in approved versions" in f for f in r.failures)