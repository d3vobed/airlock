"""Artifact domain models."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ArtifactState(str, Enum):
    REQUESTED = "REQUESTED"
    RESOLVED = "RESOLVED"
    QUARANTINED = "QUARANTINED"
    VERIFYING = "VERIFYING"
    SANDBOXED = "SANDBOXED"
    VERIFIED = "VERIFIED"
    INTERNAL = "INTERNAL"
    BUILDABLE = "BUILDABLE"
    REJECTED = "REJECTED"


class SourceKind(str, Enum):
    APPROVED_REGISTRY = "approved-registry"
    PUBLIC = "public"
    UNTRUSTED = "untrusted"


class SandboxBlock(str, Enum):
    ENV_ACCESS = "env_access"
    SSH_ACCESS = "ssh_access"
    NETWORK = "network"
    FILESYSTEM = "filesystem"


class Artifact(BaseModel):
    """An artifact under admission review."""

    package: str
    version: str
    source: str
    publisher: str | None = None
    digest: str = ""
    artifact_id: str = ""
    state: ArtifactState = ArtifactState.REQUESTED
    manifest_path: str = ""
    policy: dict = Field(default_factory=dict)
    sandbox_result: list[dict] = Field(default_factory=list)
    reason: str | None = None

    @property
    def identity(self) -> str:
        return self.artifact_id or f"{self.package}@{self.version}"
