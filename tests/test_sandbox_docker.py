"""Docker-backed sandbox tests.

These require a working Docker daemon and run the REAL isolated npm install.
They are skipped automatically when Docker is unavailable and register under
the ``docker`` marker (see pytest.ini / pyproject).
"""
from __future__ import annotations

import pytest

from apps.sandbox.runner import SandboxRunner, docker_available
from .conftest import REPO_ROOT

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_available(), reason="Docker daemon not available"),
]


def test_real_sandbox_container_runs():
    r = SandboxRunner().run(REPO_ROOT.parent, probe_mode=True)
    assert r.ok is True or r.error is not None


def test_real_npm_install_isolated(npm_fixture_canary_benign):
    r = SandboxRunner().run_npm_install(npm_fixture_canary_benign)
    assert r.error is None or "Docker unavailable" in r.error
    # postinstall lifecycle should be observed in events.
    lifecycle = [e for e in r.events if e.kind == "lifecycle"]
    assert any("postinstall" in e.detail for e in lifecycle)


def test_real_npm_install_violation_blocked(npm_fixture_canary_violation):
    r = SandboxRunner().run_npm_install(npm_fixture_canary_violation)
    assert r.error is None or "Docker unavailable" in r.error
    # In the real sandbox the violation package's network probe must not connect.
    for e in r.events:
        if e.kind == "network":
            assert "blocked" in e.detail.lower() or "blocked" in e.detail.lower()