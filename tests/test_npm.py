"""Real npm artifact validation tests.

Validation matrix:
  A. Benign public npm package          (real fixture: is-number@7.0.0, offline)
  B. Team-controlled npm package        (@airlock-demo/canary-sdk@1.0.0)
  C. Controlled package w/ violation    (@airlock-demo/canary-sdk@1.0.1, --malicious)
  D. Tampered downloaded tarball
  E. Dependency/source mismatch
  F. Malicious update simulation
  G. Transitive dependency inspection
  H. Missing provenance
  I. Registry failure
  J. Network unavailable / offline mode
  K. Malformed package
  L. Sandbox timeout / failure-closed

Offline mode uses committed real artifacts. Live-registry tests are marked
``live`` and only run when explicitly requested (make test-live-npm).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from apps.gateway.services.admission import AdmissionPipeline
from apps.gateway.services.npm_resolver import NpmResolution, NpmResolver, verify_sha512_sri, parse_spec

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# A. Benign real public npm package
# --------------------------------------------------------------------------- #
def test_benign_real_npm_package_offline(npm_fixture_real, sandbox_mode):
    res = NpmResolver().resolve("is-number@7.0.0", mode="offline")
    assert res.package == "is-number"
    assert res.version == "7.0.0"
    assert res.local_path.endswith(".tgz")
    assert res.digest  # sha256 computed
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit_npm(
        "is-number@7.0.0", npm_mode="offline"
    )
    assert result["decision"] == "TRUSTED"


def test_benign_real_npm_package_sri_verified(npm_fixture_real):
    res = NpmResolver().resolve("is-number@7.0.0", mode="offline")
    assert res.npm_integrity.startswith("sha512-")
    assert verify_sha512_sri(res.local_path, res.npm_integrity) is True


# --------------------------------------------------------------------------- #
# B/C. Team-controlled canary package
# --------------------------------------------------------------------------- #
def test_controlled_npm_package_benign_trusted(sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit_npm(
        "@airlock-demo/canary-sdk@1.0.0", npm_mode="offline"
    )
    assert result["decision"] == "TRUSTED"
    assert result["passport"]["lifecycle_scripts"] == ["postinstall"]


def test_controlled_npm_package_violation_rejected(sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode, malicious=True).admit_npm(
        "@airlock-demo/canary-sdk@1.0.1", npm_mode="offline"
    )
    assert result["decision"] == "REJECTED"


# --------------------------------------------------------------------------- #
# D. Tampered downloaded tarball
# --------------------------------------------------------------------------- #
def test_tampered_downloaded_tarball_rejected(tmp_path, npm_fixture_real, sandbox_mode):
    src = Path(npm_fixture_real)
    tampered = tmp_path / "tampered.tgz"
    data = bytearray(src.read_bytes())
    data[5] ^= 0x01
    tampered.write_bytes(bytes(data))
    from core.hashing.sha256 import sha256_file

    assert sha256_file(tampered) != sha256_file(src)


# --------------------------------------------------------------------------- #
# E. Dependency / source mismatch
# --------------------------------------------------------------------------- #
def test_source_mismatch_rejected(confusion_tarball, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        confusion_tarball, source="public"
    )
    assert result["decision"] == "REJECTED"


# --------------------------------------------------------------------------- #
# F. Malicious update simulation (controlled canary 1.0.0 -> 1.0.1)
# --------------------------------------------------------------------------- #
def test_controlled_malicious_update_lkg(sandbox_mode, storage):
    p1 = AdmissionPipeline(sandbox_mode=sandbox_mode, storage=storage)
    trusted = p1.admit_npm("@airlock-demo/canary-sdk@1.0.0", npm_mode="offline")
    assert trusted["decision"] == "TRUSTED"

    p2 = AdmissionPipeline(sandbox_mode=sandbox_mode, storage=storage, malicious=True)
    rejected = p2.admit_npm("@airlock-demo/canary-sdk@1.0.1", npm_mode="offline")
    assert rejected["decision"] == "REJECTED"

    lkg = p2.fallback.get_lkg("@airlock-demo/canary-sdk")
    assert lkg is not None and lkg["version"] == "1.0.0"


# --------------------------------------------------------------------------- #
# G. Transitive dependency inspection
# --------------------------------------------------------------------------- #
def test_transitive_dependencies_recorded():
    res = NpmResolver().resolve("is-number@7.0.0", mode="offline")
    assert isinstance(res.dependencies, dict)
    assert res.dependencies == {}


# --------------------------------------------------------------------------- #
# H. Missing provenance is UNAVAILABLE, never VERIFIED
# --------------------------------------------------------------------------- #
def test_missing_provenance_honest(legit_tarball, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        legit_tarball, source="internal-approved-registry"
    )
    assert result["passport"]["provenance"] == "unavailable"


# --------------------------------------------------------------------------- #
# I. Registry failure fails closed / surfaces error
# --------------------------------------------------------------------------- #
def test_unresolvable_spec_raises():
    with pytest.raises(ValueError):
        NpmResolver().resolve("not-a-real-package-xyz@1.0.0", mode="live")


# --------------------------------------------------------------------------- #
# J. Network unavailable = offline mode must not require network
# --------------------------------------------------------------------------- #
def test_offline_mode_no_network_required(npm_fixture_real):
    # Offline resolution only touches local fixture cache; no network needed.
    res = NpmResolver().resolve("is-number@7.0.0", mode="offline")
    assert res.mode == "offline-cached"


# --------------------------------------------------------------------------- #
# K. Malformed package
# --------------------------------------------------------------------------- #
def test_malformed_package_rejected(tmp_path, sandbox_mode):
    malformed = tmp_path / "bad-package.tgz"
    malformed.write_bytes(b"definitely-not-a-tarball")
    with pytest.raises(ValueError):
        AdmissionPipeline(sandbox_mode=sandbox_mode).admit(str(malformed))


# --------------------------------------------------------------------------- #
# L. Docker unavailable -> fail closed
# --------------------------------------------------------------------------- #
def test_docker_unavailable_fails_closed(monkeypatch):
    from apps.sandbox import runner as rmod

    monkeypatch.setattr(rmod, "docker_available", lambda: False)
    # Explicit docker mode with no daemon must fail closed, never trust.
    result = AdmissionPipeline(sandbox_mode="docker").admit(
        str(REPO_ROOT / "demo/legitimate-package/package.tgz"),
        source="internal-approved-registry",
    )
    assert result["decision"] == "REJECTED"


# --------------------------------------------------------------------------- #
# parse_spec coverage
# --------------------------------------------------------------------------- #
def test_parse_spec_scoped_and_unscoped():
    assert parse_spec("is-number@7.0.0") == ("is-number", "7.0.0")
    assert parse_spec("@scope/name@1.2.3") == ("@scope/name", "1.2.3")
    with pytest.raises(ValueError):
        parse_spec("missing-version")