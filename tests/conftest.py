"""Shared test fixtures.

Tests run against a temporary, throwaway AIRLOCK state (DB + registry dirs) so
they never touch real registry contents or the developer's own state.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from apps.gateway.config import settings  # noqa: E402
from apps.gateway.store import Storage  # noqa: E402
from apps.sandbox.policy import DEFAULT_SANDBOX_POLICY  # noqa: E402
from apps.sandbox.runner import docker_available  # noqa: E402

DEMO = REPO_ROOT / "demo"
NPM_CACHE = REPO_ROOT / "npm_cache"


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    """Point every AIRLOCK path at a throwaway directory for this test."""
    base = tmp_path / "airlock"
    for attr, sub in (
        ("db_path", "state.db"),
        ("trusted_dir", "trusted"),
        ("quarantine_dir", "quarantine"),
        ("rejected_dir", "rejected"),
        ("lkg_dir", "lkg"),
    ):
        monkeypatch.setattr(settings, attr, str(base / sub))
    settings.ensure_dirs()
    yield base
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def storage() -> Storage:
    return Storage()


@pytest.fixture
def sandbox_mode() -> str:
    return "simulate"


@pytest.fixture
def have_docker() -> bool:
    return docker_available()


@pytest.fixture
def legit_tarball() -> str:
    return str(DEMO / "legitimate-package" / "package.tgz")


@pytest.fixture
def malicious_tarball() -> str:
    return str(DEMO / "malicious-package" / "package.tgz")


@pytest.fixture
def confusion_tarball() -> str:
    return str(DEMO / "dependency-confusion" / "package.tgz")


@pytest.fixture
def tampered_tarball() -> str:
    return str(DEMO / "tampered-artifact" / "package.tgz")


@pytest.fixture
def update_tarball() -> str:
    return str(DEMO / "malicious-update" / "package.tgz")


@pytest.fixture
def npm_fixture_real() -> str:
    """A REAL npm artifact (is-number@7.0.0) committed as an offline fixture."""
    return str(NPM_CACHE / "fixtures" / "is-number@7.0.0.tgz")


@pytest.fixture
def npm_fixture_canary_benign() -> str:
    return str(NPM_CACHE / "fixtures" / "@airlock-demo__canary-sdk@1.0.0.tgz")


@pytest.fixture
def npm_fixture_canary_violation() -> str:
    return str(NPM_CACHE / "fixtures" / "@airlock-demo__canary-sdk@1.0.1.tgz")