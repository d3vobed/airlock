"""Admission pipeline orchestration.

Implements the AIRLOCK state machine:

REQUESTED → RESOLVED → QUARANTINED → VERIFYING → SANDBOXED → VERIFIED
           → INTERNAL → BUILDABLE

Failure path:

QUARANTINED → REJECTED → (LKG_FALLBACK)

An artifact that fails any check is never promoted. The decision is
deterministic and explainable.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from core.models.artifact import Artifact, ArtifactState
from core.models.decision import Decision
from core.models.passport import CheckStatus, IntegrityStatus

from ..artifact_io import copy_artifact
from ..config import settings
from ..store import Storage
from .fallback import FallbackService
from .passport import PassportService
from .policy import PolicyEngine
from .resolver import Resolver
from .sandbox import SandboxService, prepare_workspace
from .verifier import Verifier


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AdmissionPipeline:
    """Orchestrates a full admission run for one artifact."""

    def __init__(self, storage: Storage | None = None, sandbox_mode: str | None = None, malicious: bool = False):
        self.storage = storage or Storage()
        self.resolver = Resolver()
        self.policy = PolicyEngine(settings.policy_file)
        self.verifier = Verifier()
        self.sandbox = SandboxService(mode=sandbox_mode, malicious=malicious)
        self.passport = PassportService(self.storage)
        self.fallback = FallbackService(self.storage)

    def admit(
        self,
        path: str,
        source: str | None = None,
        expected_digest: str | None = None,
    ) -> dict:
        """Admit an artifact tarball. Returns the decision + passport + checks."""
        # REQUESTED -> RESOLVED
        artifact = self.resolver.resolve(path, declared_source=source)
        return self._admit_artifact(artifact, expected_digest=expected_digest)

    def admit_npm(
        self,
        spec: str,
        npm_mode: str = "auto",
        registry: str | None = None,
        source: str = "internal-approved-registry",
    ) -> dict:
        """Admit a real npm ``name@version`` artifact through the full pipeline."""
        artifact = self.resolver.resolve_npm(spec, npm_mode=npm_mode, registry=registry, source=source)
        return self._admit_artifact(artifact)

    def _admit_artifact(self, artifact: Artifact, expected_digest: str | None = None) -> dict:
        # QUARANTINED
        artifact.state = ArtifactState.QUARANTINED
        quarantine_path = self.resolver.stage_to_quarantine(artifact)
        artifact.manifest_path = quarantine_path
        self.storage.save_artifact(artifact.model_dump(exclude={"policy", "sandbox_result", "reason"}))
        self._log_decision(artifact, Decision.QUARANTINED, "quarantined for admission review")

        checks: list[dict] = []

        # VERIFYING — identity + integrity
        artifact.state = ArtifactState.VERIFYING
        identity_status = CheckStatus.PASSED if artifact.artifact_id.startswith("airlock:sha256:") else CheckStatus.FAILED
        checks.append({"name": "identity", "status": identity_status.value,
                       "detail": f"artifact identity established: {artifact.artifact_id[:32]}…"})

        vr = self.verifier.verify(artifact, expected_digest=expected_digest)
        checks.append({"name": "integrity", "status": vr.integrity.value,
                       "detail": vr.detail, "expected_digest": expected_digest, "computed_digest": artifact.digest})

        integrity = vr.integrity

        # npm registry integrity (Subresource Integrity) verification
        npm_integrity_checked = False
        if artifact.ecosystem == "npm" and artifact.npm_integrity:
            from .npm_resolver import verify_sha512_sri

            sri_ok = verify_sha512_sri(artifact.manifest_path, artifact.npm_integrity)
            npm_integrity_checked = True
            if sri_ok:
                checks.append({"name": "npm_integrity", "status": "verified",
                               "detail": "npm Subresource Integrity (sha512) matches downloaded artifact"})
            else:
                integrity = IntegrityStatus.FAILED
                checks.append({"name": "npm_integrity", "status": "failed",
                               "detail": "npm SRI does NOT match downloaded artifact bytes"})

        if artifact.ecosystem == "npm" and not artifact.npm_integrity:
            checks.append({"name": "npm_integrity", "status": "unavailable",
                           "detail": "no npm SRI provided by registry for this artifact"})

        # Lifecycle script analysis
        if artifact.ecosystem == "npm":
            scripts = artifact.lifecycle_scripts or []
            if scripts:
                lifecycle_detail = f"npm lifecycle scripts present: {', '.join(scripts)} (executed only inside sandbox)"
                live_status = "passed"
            else:
                lifecycle_detail = "no npm install-time lifecycle scripts (preinstall/install/postinstall/prepare)"
                live_status = "passed"
            checks.append({"name": "lifecycle", "status": live_status, "detail": lifecycle_detail})
            artifact.observations.append(lifecycle_detail)
        else:
            checks.append({"name": "lifecycle", "status": "skipped", "detail": "non-npm artifact"})

        # Trusted-registry tamper check: if the same package+version is already
        # trusted internally, the exact bytes MUST match. A different digest
        # means the artifact was modified/replaced after admission.
        trusted_copy = self._trusted_copy(artifact)
        if trusted_copy and trusted_copy == artifact.digest:
            checks.append({"name": "reuse", "status": "passed",
                           "detail": "artifact matches the existing trusted copy (digest identical)"})
        elif trusted_copy:
            integrity = IntegrityStatus.FAILED
            checks.append({"name": "reuse", "status": "failed",
                           "detail": "TAMPERED: same package+version is already trusted with a different digest"})
        else:
            checks.append({"name": "reuse", "status": "skipped",
                           "detail": "no existing trusted copy for this package+version"})

        # source check
        source_status = CheckStatus.PASSED if artifact.source in ("internal-approved-registry", "approved-registry") else CheckStatus.FAILED
        checks.append({"name": "source", "status": source_status.value,
                       "detail": f"source '{artifact.source}' {'approved' if source_status == CheckStatus.PASSED else 'NOT approved'}"})

        # policy check
        policy_result = self.policy.evaluate(artifact)
        checks.append({"name": "policy", "status": CheckStatus.PASSED.value if policy_result.passed else CheckStatus.FAILED.value,
                       "detail": "; ".join(policy_result.failures) if not policy_result.passed else "policy satisfied"})
        policy_status = CheckStatus.PASSED if policy_result.passed else CheckStatus.FAILED

        hard_failures = [
            identity_status != CheckStatus.PASSED,
            integrity == IntegrityStatus.FAILED,
            source_status != CheckStatus.PASSED,
            policy_status != CheckStatus.PASSED,
        ]

        # QUARANTINED → SANDBOXED (only if hard checks pass)
        sandbox_status = CheckStatus.SKIPPED
        sandbox_mode = "none"
        sandbox_result = {}
        npm_install = artifact.ecosystem == "npm"
        if not any(hard_failures):
            try:
                workspace = prepare_workspace(artifact, marker="admit")
                result, sandbox_mode, sandbox_status = self.sandbox.execute(
                    workspace, artifact, npm_install=npm_install
                )
                sandbox_result = result.to_dict() if result else {}
                sandbox_result["mode"] = sandbox_mode
                sandbox_result["npm_install"] = npm_install or None
                checks.append({
                    "name": "sandbox",
                    "status": sandbox_status.value,
                    "detail": self._sandbox_summary(result) if result else "sandbox failed",
                })
                if result.error:
                    checks[-1]["detail"] = result.error
                if result:
                    for ev in result.events:
                        if ev.kind not in ("behavior", "install", "lifecycle") or ev.detail not in artifact.observations:
                            artifact.observations.append(f"{ev.kind}: {ev.detail}")
            except Exception as e:  # noqa: BLE001
                sandbox_status = CheckStatus.FAILED
                sandbox_result = {"error": str(e), "ok": False}
                checks.append({"name": "sandbox", "status": "failed", "detail": f"sandbox error: {e}"})
        else:
            checks.append({"name": "sandbox", "status": "skipped", "detail": "sandbox skipped: earlier checks failed"})

        sandbox_failed = sandbox_status == CheckStatus.FAILED or not sandbox_result.get("ok", True)

        # Decision: deterministic and explainable.
        reasons = []
        if identity_status != CheckStatus.PASSED:
            reasons.append("identity could not be established")
        if integrity == IntegrityStatus.FAILED:
            reasons.append("integrity verification failed (digest mismatch)")
        if source_status != CheckStatus.PASSED:
            reasons.append(f"source '{artifact.source}' not approved (possible dependency confusion)")
        if policy_status != CheckStatus.PASSED:
            reasons.append("policy not satisfied")
        if sandbox_failed:
            reasons.append("sandbox detected suspicious behavior or failed closed")

        if reasons:
            artifact.state = ArtifactState.REJECTED
            artifact.reason = "; ".join(reasons)
            self.storage.save_artifact(artifact.model_dump(exclude={"policy", "sandbox_result"}))
            self._log_decision(artifact, Decision.REJECTED, artifact.reason)
            decision = Decision.REJECTED.value
            # Malicious update: check LKG
            lkg = self.fallback.get_lkg(artifact.package)
            self._maybe_reject_copy(artifact)
        else:
            # VERIFIED → INTERNAL → BUILDABLE (promote)
            artifact.state = ArtifactState.INTERNAL
            self._promote(artifact)
            artifact.state = ArtifactState.BUILDABLE
            artifact.reason = None
            self.storage.save_artifact(artifact.model_dump(exclude={"policy", "sandbox_result", "reason"}))
            self._log_decision(artifact, Decision.TRUSTED, "all admission checks passed")
            decision = Decision.TRUSTED.value
            lkg = {"is_lkg": True, **self.fallback.get_lkg(artifact.package)}

        passport = self.passport.generate(
            artifact=artifact,
            identity_status=identity_status,
            integrity=integrity,
            source_status=source_status,
            policy_status=policy_status,
            sandbox_status=sandbox_status,
            sandbox_mode=sandbox_mode,
            sandbox_result=sandbox_result,
            decision=decision,
            checks=checks,
        )

        return {
            "artifact_id": artifact.artifact_id,
            "package": artifact.package,
            "version": artifact.version,
            "digest": artifact.digest,
            "source": artifact.source,
            "state": artifact.state.value,
            "decision": decision,
            "reason": artifact.reason,
            "checks": checks,
            "sandbox": sandbox_result,
            "lkg": lkg,
            "passport": passport.model_dump(),
            "registry": artifact.registry or ("npm" if artifact.ecosystem == "npm" else None),
            "tarball_url": artifact.tarball_url or None,
            "timestamp": _now(),
        }

    def _promote(self, artifact: Artifact) -> None:
        """Store the exact artifact bytes in the trusted registry + LKG."""
        dest = Path(settings.trusted_dir) / f"{artifact.package.replace('/', '__')}@{artifact.version}.tgz"
        copy_artifact(artifact.manifest_path, dest)
        artifact.manifest_path = str(dest)
        self.fallback.record_lkg(artifact)

    def _trusted_copy(self, artifact: Artifact) -> str | None:
        """Return the digest of the existing trusted copy for package+version."""
        from core.hashing.sha256 import sha256_file

        dest = Path(settings.trusted_dir) / f"{artifact.package.replace('/', '__')}@{artifact.version}.tgz"
        if dest.exists():
            return sha256_file(dest)
        return None

    def _maybe_reject_copy(self, artifact: Artifact) -> None:
        dest = Path(settings.rejected_dir) / f"{artifact.package.replace('/', '__')}@{artifact.version}.tgz"
        copy_artifact(artifact.manifest_path, dest)

    def _sandbox_summary(self, result) -> str:
        if result.suspicious:
            _kinds = [e for e in result.events if not e.blocked]
            if not _kinds:
                _kinds = [e for e in result.events if e.kind == "behavior"]
            details = ", ".join(sorted({e.detail for e in _kinds}))
            return f"suspicious behavior detected: {details or 'unknown'}"
        if result.error:
            return result.error
        return f"sandbox completed cleanly ({len(result.events)} events)"

    def _log_decision(self, artifact: Artifact, decision: Decision, reason: str | None) -> None:
        self.storage.add_decision({
            "artifact_id": artifact.artifact_id,
            "package": artifact.package,
            "version": artifact.version,
            "decision": decision.value,
            "reason": reason,
        })