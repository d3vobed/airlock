"""Pydantic request/response models for the AIRLOCK API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from core.models.decision import Decision


class AdmitRequest(BaseModel):
    path: str = Field(description="Path to the artifact tarball (local or registry path)")
    source: str | None = Field(None, description="Declared source of the artifact, e.g. 'public' or 'internal-approved-registry'")
    expected_digest: str | None = Field(None, description="Expected SHA-256 digest, if pinning")
    sandbox_mode: str | None = Field(None, description="Sandbox isolation mode: auto | docker | simulate")
    malicious: bool = Field(False, description="Demo flag: mark package as malicious for sandbox simulation")


class VerifyRequest(BaseModel):
    path: str
    expected_digest: str
    source: str | None = None


class PromoteRequest(BaseModel):
    passthrough: str | None = None
    require_lkg: bool = Field(False, description="If true, promotion requires a Last Known Good record exists")


class RollbackRequest(BaseModel):
    package: str
    target_version: str | None = Field(None, description="Optional explicit rollback version")


class PassportResponse(BaseModel):
    artifact_id: str
    package: str
    version: str
    digest: str
    source: str
    decision: str
    status: str
    timestamp: str
    checks: list[dict[str, Any]]
    sandbox: dict[str, Any]


class DecisionResponse(BaseModel):
    artifact_id: str
    package: str
    version: str
    decision: Decision
    reason: str | None = None
    state: str = ""
    details: dict[str, Any] = Field(default_factory=dict)