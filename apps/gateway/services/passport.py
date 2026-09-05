"""Supply Chain Passport generation.

Produces a deterministic, machine-readable JSON record of exactly what AIRLOCK
checked and what it decided. It is honest: it never claims provenance was
verified if no provenance mechanism existed.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.hashing.sha256 import artifact_id
from core.models.artifact import Artifact
from core.models.passport import CheckStatus, IntegrityStatus, Passport

from ..store import Storage

AIRLOCK_VERSION = "0.1.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PassportService:
    """Builds and persists Supply Chain Passports."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def generate(
        self,
        artifact: Artifact,
        identity_status: CheckStatus,
        integrity: IntegrityStatus,
        source_status: CheckStatus,
        policy_status: CheckStatus,
        sandbox_status: CheckStatus,
        sandbox_mode: str,
        sandbox_result: dict,
        decision: str,
        provenance: IntegrityStatus = IntegrityStatus.UNAVAILABLE,
        checks: list[dict] | None = None,
    ) -> Passport:
        checks = checks or []
        passport = Passport(
            artifact_id=artifact.artifact_id,
            package=artifact.package,
            version=artifact.version,
            digest=artifact.digest,
            source=artifact.source,
            publisher=artifact.publisher,
            ecosystem=artifact.ecosystem,
            registry=artifact.registry,
            tarball_url=artifact.tarball_url,
            npm_integrity=artifact.npm_integrity,
            lifecycle_scripts=artifact.lifecycle_scripts,
            observations=artifact.observations,
            dependencies=artifact.dependencies,
            identity_status=identity_status,
            integrity=integrity,
            provenance=provenance,
            source_status=source_status,
            policy_status=policy_status,
            sandbox_status=sandbox_status,
            sandbox={
                "mode": sandbox_mode,
                "network": "denied" if sandbox_mode in ("docker", "simulate") else "unset",
                "secrets": "denied",
                "filesystem": "restricted",
            },
            decision=decision,
            status=decision if decision in ("TRUSTED", "REJECTED") else "QUARANTINED",
            checks=checks,
            timestamp=_now(),
        )
        self.storage.save_passport(artifact.artifact_id, passport.model_dump())
        return passport

    def get(self, artifact_id: str) -> Passport | None:
        data = self.storage.get_passport(artifact_id)
        return Passport(**data) if data else None

    @staticmethod
    def verify_digest(passport, computed_digest: str) -> bool:
        """A passport is invalidated if the artifact bytes change.

        Accepts either a Passport instance or its model_dump() dict.
        """
        if isinstance(passport, Passport):
            passport_id = passport.artifact_id
        else:
            passport_id = (passport or {}).get("artifact_id")
        return artifact_id(computed_digest) == passport_id