"""Supply Chain Passport model.

The passport is a machine-readable JSON record describing exactly what
AIRLOCK checked about an artifact, the outcome of each check, and the
final admission decision. It does NOT claim things AIRLOCK did not
actually verify.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class IntegrityStatus(str, Enum):
    VERIFIED = "verified"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"


class Passport(BaseModel):
    artifact_id: str
    package: str
    version: str
    digest: str
    source: str
    publisher: str | None = None

    # Ecosystem extension (npm / pypi / ...)
    ecosystem: str = "generic"
    registry: str = ""
    tarball_url: str = ""
    npm_integrity: str = ""
    lifecycle_scripts: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    dependencies: dict = Field(default_factory=dict)

    identity_status: CheckStatus = CheckStatus.SKIPPED
    integrity: IntegrityStatus = IntegrityStatus.UNAVAILABLE
    provenance: IntegrityStatus = IntegrityStatus.UNAVAILABLE
    source_status: CheckStatus = CheckStatus.SKIPPED
    policy_status: CheckStatus = CheckStatus.SKIPPED
    sandbox_status: CheckStatus = CheckStatus.SKIPPED

    sandbox: dict = Field(
        default_factory=lambda: {
            "network": "denied",
            "secrets": "denied",
            "filesystem": "restricted",
        }
    )

    decision: str = "REJECTED"
    status: str = "UNAVAILABLE"
    checks: list[dict] = Field(default_factory=list)
    timestamp: str = ""
