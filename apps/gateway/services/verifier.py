"""Verifier — integrity and identity verification.

Checks that the exact bytes of an artifact match a previously recorded digest
(if one exists) and that its computed digest matches the artifact identity.
"""
from __future__ import annotations

from pathlib import Path

from core.hashing.sha256 import normalize_digest, sha256_file
from core.models.artifact import Artifact
from core.models.passport import IntegrityStatus


class VerificationResult:
    def __init__(self, passed: bool, integrity: IntegrityStatus, detail: str):
        self.passed = passed
        self.integrity = integrity  # verified | unavailable | failed
        self.detail = detail

    def __repr__(self) -> str:
        return f"VerificationResult(passed={self.passed}, integrity={self.integrity})"


class Verifier:
    """Verifies artifact integrity against an expected digest."""

    def verify(self, artifact: Artifact, expected_digest: str | None = None) -> VerificationResult:
        computed = artifact.digest
        if not computed:
            return VerificationResult(False, IntegrityStatus.FAILED, "no digest calculated")

        if expected_digest:
            if normalize_digest(computed) == normalize_digest(expected_digest):
                return VerificationResult(True, IntegrityStatus.VERIFIED, "digest matches expected")
            return VerificationResult(
                False,
                IntegrityStatus.FAILED,
                f"digest mismatch: expected {expected_digest}, got {computed}",
            )

        # No expected digest configured: integrity is UNAVAILABLE (not PASS).
        return VerificationResult(
            True, IntegrityStatus.UNAVAILABLE, "no expected digest configured; computed only"
        )

    def verify_file_against(self, path: str | Path, expected_digest: str) -> VerificationResult:
        computed = sha256_file(path)
        if normalize_digest(computed) == normalize_digest(expected_digest):
            return VerificationResult(True, IntegrityStatus.VERIFIED, "digest matches expected")
        return VerificationResult(
            False,
            IntegrityStatus.FAILED,
            f"digest mismatch: expected {expected_digest}, got {computed}",
        )
