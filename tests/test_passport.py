"""Supply Chain Passport tests."""
from __future__ import annotations

import pytest

from core.models.passport import CheckStatus, IntegrityStatus, Passport
from core.hashing.sha256 import sha256_file, artifact_id
from apps.gateway.services.admission import AdmissionPipeline
from apps.gateway.services.passport import PassportService


def test_passport_generated_for_trusted_artifact(legit_tarball, sandbox_mode, storage):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        legit_tarball, source="internal-approved-registry"
    )
    p = result["passport"]
    assert p["artifact_id"].startswith("airlock:sha256:")
    assert p["package"] == "@naijapay/payment-sdk"
    assert p["version"] == "2.1.0"
    assert p["digest"] == sha256_file(legit_tarball)
    assert p["status"] == "TRUSTED"
    assert p["decision"] == "TRUSTED"
    assert any(c["name"] == "identity" for c in p["checks"])
    assert any(c["name"] == "integrity" for c in p["checks"])
    assert any(c["name"] == "sandbox" for c in p["checks"])


def test_passport_persisted_and_retrievable(legit_tarball, sandbox_mode, storage):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode, storage=storage).admit(
        legit_tarball, source="internal-approved-registry"
    )
    fetched = PassportService(storage).get(result["artifact_id"])
    assert fetched is not None
    assert fetched.artifact_id == result["artifact_id"]


def test_passport_rejected_honest_status(malicious_tarball, sandbox_mode, storage):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode, malicious=True).admit(
        malicious_tarball, source="internal-approved-registry"
    )
    p = result["passport"]
    assert p["status"] == "REJECTED"
    # A rejected artifact never falsely claims integrity/status as TRUSTED.
    assert p["status"] != "TRUSTED"


def test_passport_sandbox_mode_honestly_reported(legit_tarball, sandbox_mode, storage):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        legit_tarball, source="internal-approved-registry"
    )
    mode = result["passport"]["sandbox"]["mode"]
    assert mode in ("simulate", "docker")  # never fabricates a mode


def test_passport_does_not_claim_unverified_provenance(legit_tarball, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        legit_tarball, source="internal-approved-registry"
    )
    # No provenance mechanism exists, so provenance must be unavailable, never verified.
    assert result["passport"]["provenance"] == "unavailable"


def test_passport_invalidated_by_byte_change(legit_tarball, tmp_path, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        legit_tarball, source="internal-approved-registry"
    )
    passport = result["passport"]

    modified = tmp_path / "m.tgz"
    data = bytearray(open(legit_tarball, "rb").read())
    data[25] ^= 0x01
    modified.write_bytes(bytes(data))

    assert sha256_file(modified) != passport["digest"]
    assert artifact_id(sha256_file(modified)) != passport["artifact_id"]
    assert PassportService.verify_digest(passport, sha256_file(modified)) is False