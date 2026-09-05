"""Sandbox isolation tests.

These exercise the sandbox orchestration service. In CI (no Docker daemon) the
sandbox falls back to deterministic simulation; the real Docker-backed sandbox
is covered by tests/test_sandbox_docker.py marked ``docker``.
"""
from __future__ import annotations

import pytest

from core.models.artifact import Artifact
from apps.gateway.services.sandbox import SandboxService

from .conftest import REPO_ROOT


def _art(package="@naijapay/loyalty-sdk", source="internal-approved-registry", publisher="naijapay") -> Artifact:
    return Artifact(
        package=package,
        version="1.0.0",
        source=source,
        publisher=publisher,
        digest="x" * 64,
        manifest_path=str(REPO_ROOT / "demo/malicious-package/package.tgz"),
    )


def test_malicious_sandbox_behavior_blocked():
    svc = SandboxService(mode="simulate", malicious=True)
    result, mode, status = svc.execute("ignored-workspace", _art())
    assert result.suspicious is True
    assert result.ok is False
    assert status.value == "failed"
    assert mode == "simulate"


def test_benign_sandbox_completes_cleanly():
    svc = SandboxService(mode="simulate", malicious=False)
    result, mode, status = svc.execute("ignored-workspace", _art())
    assert result.ok is True
    assert result.suspicious is False
    assert status.value == "passed"


def test_sandbox_never_returns_pass_on_error():
    svc = SandboxService(mode="docker-unknown-mode-xyz", malicious=False)
    result, mode, status = svc.execute("ignored-workspace", _art())
    # Unknown mode must FAIL CLOSED, never trust.
    assert result.ok is False
    assert status.value in ("failed",)


def test_sandbox_blocked_events_documented():
    svc = SandboxService(mode="simulate", malicious=True)
    result, _, _ = svc.execute("ignored-workspace", _art())
    blocked = result.to_dict()["blocked_attempts"]
    assert len(blocked) >= 4
    kinds = {e["kind"] for e in blocked}
    assert {"env_access", "ssh_access", "network", "filesystem"} <= kinds


def test_sandbox_docker_unavailable_fails_closed(monkeypatch):
    # Simulate Docker being unavailable while explicitly in docker mode.
    from apps.sandbox import runner as rmod

    monkeypatch.setattr(rmod, "docker_available", lambda: False)
    svc = SandboxService(mode="docker")
    result, mode, status = svc.execute(str(REPO_ROOT / "demo"), _art())
    assert result.error and "Docker unavailable" in result.error
    assert status.value == "failed"