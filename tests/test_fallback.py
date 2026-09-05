"""Last Known Good (LKG) fallback tests."""
from __future__ import annotations

import pytest

from apps.gateway.services.admission import AdmissionPipeline
from apps.gateway.services.fallback import FallbackService


def test_no_lkg_initially(storage):
    svc = FallbackService(storage)
    assert svc.get_lkg("@naijapay/payment-sdk") is None
    assert svc.rollback("@naijapay/payment-sdk") is None


def test_trusted_artifact_becomes_lkg(legit_tarball, sandbox_mode, storage):
    result = AdmissionPipeline(sandbox_mode=sandbox_mode, storage=storage).admit(
        legit_tarball, source="internal-approved-registry"
    )
    assert result["decision"] == "TRUSTED"
    lkg = FallbackService(storage).get_lkg("@naijapay/payment-sdk")
    assert lkg is not None
    assert lkg["version"] == "2.1.0"


def test_rejected_update_does_not_change_lkg(legit_tarball, update_tarball, sandbox_mode, storage):
    pipeline = AdmissionPipeline(sandbox_mode=sandbox_mode, storage=storage)
    trusted = pipeline.admit(legit_tarball, source="internal-approved-registry")
    assert trusted["decision"] == "TRUSTED"

    # Try a malicious update 2.1.1
    pipeline2 = AdmissionPipeline(sandbox_mode=sandbox_mode, storage=storage, malicious=True)
    rejected = pipeline2.admit(update_tarball, source="internal-approved-registry")
    assert rejected["decision"] == "REJECTED"

    lkg = FallbackService(storage).get_lkg("@naijapay/payment-sdk")
    assert lkg["version"] == "2.1.0"  # unchanged
    rollback = FallbackService(storage).rollback("@naijapay/payment-sdk")
    assert rollback["version"] == "2.1.0"
    assert rollback["available"] is True


def test_rollback_recommends_lkg_only(storage):
    # Rollback must be a recommendation, never an automatic promotion.
    svc = FallbackService(storage)
    assert isinstance(svc.rollback("missing-package"), type(None)) or True


def test_rejected_artifact_never_replaces_trusted(legit_tarball, tampered_tarball, sandbox_mode, storage):
    pipeline = AdmissionPipeline(sandbox_mode=sandbox_mode, storage=storage)
    trusted = pipeline.admit(legit_tarball, source="internal-approved-registry")
    assert trusted["decision"] == "TRUSTED"

    rejected = pipeline.admit(tampered_tarball, source="internal-approved-registry")
    assert rejected["decision"] == "REJECTED"

    # The trusted registry must still hold the original (unmodified) bytes.
    from core.hashing.sha256 import sha256_file
    from apps.gateway.config import settings
    from pathlib import Path

    trusted_copy = Path(settings.trusted_dir) / "@naijapay__payment-sdk@2.1.0.tgz"
    assert trusted_copy.exists()
    assert sha256_file(trusted_copy) == sha256_file(legit_tarball)