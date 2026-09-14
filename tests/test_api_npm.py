"""Gateway API-level admission tests (route pass-through parity).

Regression guard: the /artifacts/admit/npm route must forward the ``malicious``
demo hint so simulate mode truthfully rejects a controlled violation, while the
benign team package stays trusted — the same semantics the CLI and UI demo use.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi.testclient")

from fastapi.testclient import TestClient

from apps.gateway.deps import app_state
from apps.gateway.main import app
from apps.gateway.store import Storage

client = TestClient(app)


@pytest.fixture()
def isolated_api_state(tmp_path, monkeypatch):
    """Point the gateway AppState singletons at a throwaway DB/storage."""
    base = tmp_path / "api"
    base.mkdir(parents=True, exist_ok=True)
    store = Storage(str(base / "state.db"))
    monkeypatch.setattr(app_state, "storage", store)
    monkeypatch.setattr(app_state, "passport_svc", __import__(
        "apps.gateway.services.passport", fromlist=["PassportService"]
    ).PassportService(store))
    monkeypatch.setattr(app_state, "fallback_svc", __import__(
        "apps.gateway.services.fallback", fromlist=["FallbackService"]
    ).FallbackService(store))
    return client


def test_api_npm_canary_benign_trusted(isolated_api_state):
    r = isolated_api_state.post(
        "/artifacts/admit/npm",
        json={
            "spec": "@airlock-demo/canary-sdk@1.0.0",
            "npm_mode": "offline",
            "sandbox_mode": "simulate",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "TRUSTED"
    assert body["sandbox"]["mode"] == "simulate"
    assert any(c["name"] == "lifecycle" for c in body["checks"])


def test_api_npm_canary_violation_rejected_via_malicious_hint(isolated_api_state):
    r = isolated_api_state.post(
        "/artifacts/admit/npm",
        json={
            "spec": "@airlock-demo/canary-sdk@1.0.1",
            "npm_mode": "offline",
            "sandbox_mode": "simulate",
            "malicious": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "REJECTED"
    assert "sandbox" in (body["reason"] or "").lower()


def test_api_npm_real_package_offline_trusted(isolated_api_state):
    r = isolated_api_state.post(
        "/artifacts/admit/npm",
        json={"spec": "is-number@7.0.0", "npm_mode": "offline", "sandbox_mode": "simulate"},
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "TRUSTED"