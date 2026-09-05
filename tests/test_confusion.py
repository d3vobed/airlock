"""End-to-end admission scenarios: legitimate, confusion, tampering, malicious,
malicious update, LKG fallback, and passport invalidation.

These drive the real AdmissionPipeline using committed demo fixtures.
"""
from __future__ import annotations

import pytest

from core.models.passport import CheckStatus
from apps.gateway.services.admission import AdmissionPipeline
from apps.gateway.services.passport import PassportService
from core.hashing.sha256 import sha256_file


def test_legitimate_package_trusted(legit_tarball, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        legit_tarball, source="internal-approved-registry"
    )
    assert result["decision"] == "TRUSTED"
    assert result["passport"]["status"] == "TRUSTED"
    assert result["passport"]["integrity"] in ("verified", "unavailable")


def test_malicious_package_rejected(malicious_tarball, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode, malicious=True).admit(
        malicious_tarball, source="internal-approved-registry"
    )
    assert result["decision"] == "REJECTED"
    assert result["reason"] and "sandbox" in result["reason"]


def test_dependency_confusion_rejected(confusion_tarball, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        confusion_tarball, source="public"
    )
    assert result["decision"] == "REJECTED"
    assert "source" in (result["reason"] or "").lower() + " " + " ".join(
        c["detail"] for c in result["checks"]
    ).lower()


def test_tampered_artifact_rejected(tampered_tarball, legit_tarball, sandbox_mode):
    # First trust the original so its digest/passport exist.
    first = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        legit_tarball, source="internal-approved-registry"
    )
    assert first["decision"] == "TRUSTED"

    passport = first["passport"]
    # Verify the original passport against original bytes -> valid.
    assert sha256_file(legit_tarball) == passport["digest"]

    # Modified artifact (one byte changed) must be rejected.
    second = AdmissionPipeline(sandbox_mode=sandbox_mode).admit(
        tampered_tarball, source="internal-approved-registry"
    )
    assert second["decision"] == "REJECTED"


def test_passport_invalidated_by_mutation(legit_tarball, tmp_path, sandbox_mode):
    pipeline = AdmissionPipeline(sandbox_mode=sandbox_mode)
    trusted = pipeline.admit(legit_tarball, source="internal-approved-registry")
    passport = trusted["passport"]

    # Mutate one byte of the artifact.
    mutated = tmp_path / "mutated.tgz"
    data = bytearray(open(legit_tarball, "rb").read())
    data[10] ^= 0x01
    mutated.write_bytes(bytes(data))

    # The passport (built for a specific artifact identity) must NOT validate.
    assert not PassportService.verify_digest(passport, sha256_file(mutated))


def test_malicious_update_rejected_lkg_available(legit_tarball, update_tarball, sandbox_mode):
    pipeline1 = AdmissionPipeline(sandbox_mode=sandbox_mode)
    trusted = pipeline1.admit(legit_tarball, source="internal-approved-registry")
    assert trusted["decision"] == "TRUSTED"

    pipeline2 = AdmissionPipeline(sandbox_mode=sandbox_mode, malicious=True)
    rejected = pipeline2.admit(update_tarball, source="internal-approved-registry")
    assert rejected["decision"] == "REJECTED"

    lkg = pipeline2.fallback.get_lkg("@naijapay/payment-sdk")
    assert lkg is not None
    assert lkg["version"] == "2.1.0"  # last known good, NOT the failed update
    assert lkg["version"] != "2.1.1"

    rollback = pipeline2.fallback.rollback("@naijapay/payment-sdk")
    assert rollback is not None and rollback["available"] is True


def test_failed_artifact_never_promoted(malicious_tarball, sandbox_mode):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode, malicious=True).admit(
        malicious_tarball, source="internal-approved-registry"
    )
    assert result["decision"] == "REJECTED"
    trusted_dir = __import__("apps.gateway.config", fromlist=["settings"]).settings.trusted_dir
    assert not list(__import__("pathlib", fromlist=["Path"]).Path(trusted_dir).glob("*.tgz"))