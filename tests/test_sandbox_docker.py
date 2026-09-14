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
    if r.error:
        return
    assert r.ok is True, r.stdout
    # postinstall lifecycle MUST have been observed (scripts actually ran).
    lifecycle = [e for e in r.events if e.kind == "lifecycle"]
    assert any("postinstall" in e.detail for e in lifecycle), r.stdout


def test_real_npm_install_violation_blocked(npm_fixture_canary_violation):
    r = SandboxRunner().run_npm_install(npm_fixture_canary_violation)
    assert r.error is None or "Docker unavailable" in r.error
    if r.error:
        return
    # The violation package's postinstall attempts outbound network; policy is
    # allow_network=false so the attempt must be DETECTED (rejected).
    assert r.ok is False, r.stdout
    assert any(e.kind == "network" and "blocked" in e.detail.lower() for e in r.events), r.stdout
    assert r.suspicious is True, r.stdout