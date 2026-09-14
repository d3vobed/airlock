"""Authoritative digest pins (epic #16 / A6).

demo/digests.json is the canonical byte-level pin set for every fixture.
These tests verify that (a) the pins match the exact committed bytes and
(b) the offline resolver reuse path enforces the pins (fixture drift/tampering
is refused rather than silently reused).
"""

from __future__ import annotations

import json

import pytest

from core.hashing.sha256 import sha256_file
from apps.gateway.services.npm_resolver import NpmResolver, REPO_ROOT, load_authoritative_pins

FIXTURES = REPO_ROOT / "npm_cache" / "fixtures"


def _pins() -> dict:
    data = json.loads((REPO_ROOT / "demo" / "digests.json").read_text())
    return data["registry-pins"]


@pytest.mark.parametrize(
    "slug",
    [
        "is-number@7.0.0",
        "@airlock-demo/canary-sdk@1.0.0",
        "@airlock-demo/canary-sdk@1.0.1",
    ],
)
def test_pins_match_committed_fixture_bytes(slug):
    pin = _pins()[slug]
    tgz = FIXTURES / f"{slug.replace('/', '__')}.tgz"
    assert tgz.exists()
    assert pin["sha256"] == sha256_file(tgz)
    assert pin["sha512"].startswith("sha512-")
    assert len(pin["sha1"]) == 40


def test_offline_resolver_reuse_enforces_pin():
    res = NpmResolver().resolve("is-number@7.0.0", mode="offline")
    assert res.digest == _pins()["is-number@7.0.0"]["sha256"]
    assert res.local_path.endswith("is-number@7.0.0.tgz")


def test_pin_mismatch_raises(tmp_path):
    resolver = NpmResolver(cache_dir=tmp_path / "npm_cache")
    meta_dir = tmp_path / "npm_cache" / "metadata"
    fx_dir = tmp_path / "npm_cache" / "fixtures"
    resolver.meta_dir = meta_dir
    resolver.fixtures_dir = fx_dir
    fx_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)
    (fx_dir / "is-number@7.0.0.tgz").write_bytes(b"tampered bytes")
    (meta_dir / "is-number@7.0.0.json").write_text(
        json.dumps({})
    )
    with pytest.raises(RuntimeError, match="TAMPERED"):
        resolver.resolve("is-number@7.0.0", mode="offline")


def test_missing_pin_file_is_benign(tmp_path, monkeypatch):
    monkeypatch.setattr("apps.gateway.services.npm_resolver.DIGESTS_FILE", tmp_path / "nope.json")
    assert load_authoritative_pins() == {}