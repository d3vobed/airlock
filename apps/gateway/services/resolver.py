"""Resolver / Fetcher.

Resolves an admission request into a concrete local artifact file and its
identity metadata. Supports two forms:

  local tarball
      path supplied directly (demo fixtures)

  npm spec
      name@version resolved via the real npm registry (or cached fixture).
      The exact bytes downloaded are quarantined — there is no second copy.

When AIRLOCK's resolver fetches from the npm registry on behalf of the
organization, the source is "internal-approved-registry" (the org's
authorized gateway), matching the original architecture:
    npm registry → AIRLOCK resolver → quarantine → trusted internal cache.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from core.hashing.sha256 import artifact_id, sha256_file
from core.models.artifact import Artifact, ArtifactState, SourceKind

from ..artifact_io import describe_artifact, read_package_json
from ..config import settings
from .npm_resolver import NpmResolver, parse_spec


class Resolver:
    """Resolves an admit request into a resolved Artifact record."""

    def __init__(self, approved_dir: str | None = None):
        self.approved_dir = Path(approved_dir) if approved_dir else None
        self.npm_resolver = NpmResolver()

    def resolve(self, path: str, declared_source: str | None = None) -> Artifact:
        """Build a RESOLVED artifact from a local tarball path."""
        path = Path(path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"artifact not found: {path}")

        meta = describe_artifact(path)
        if not meta.get("package") or not meta.get("version"):
            raise ValueError("artifact package.json missing name/version")

        digest = sha256_file(path)
        pub = meta.get("publisher")
        source = declared_source or self._infer_source(path, pub)

        return Artifact(
            package=meta["package"],
            version=meta["version"],
            source=source,
            publisher=pub,
            digest=digest,
            artifact_id=artifact_id(digest),
            state=ArtifactState.RESOLVED,
            manifest_path=str(path),
        )

    def resolve_npm(
        self,
        spec: str,
        npm_mode: str = "auto",
        registry: str | None = None,
        source: str = "internal-approved-registry",
    ) -> Artifact:
        """Resolve an npm ``name@version`` spec to an exact, quarantined artifact.

        Downloads the exact tarball via NpmResolver (or uses a cached fixture),
        computes SHA-256, and populates all npm-specific fields on the artifact.
        """
        res = self.npm_resolver.resolve(spec, mode=npm_mode, registry=registry)
        return Artifact(
            package=res.package,
            version=res.version,
            source=source,
            publisher=res.publisher,
            digest=res.digest,
            artifact_id=artifact_id(res.digest),
            state=ArtifactState.RESOLVED,
            manifest_path=res.local_path,
            ecosystem=res.ecosystem,
            registry=res.registry,
            tarball_url=res.tarball_url,
            npm_integrity=res.npm_integrity,
            lifecycle_scripts=NpmResolver.lifecycle_scripts({"scripts": res.lifecycle_scripts}),
            dependencies=res.dependencies,
        )

    def _infer_source(self, path: Path, publisher: str | None) -> str:
        if self.approved_dir and self.approved_dir in path.parents:
            return "internal-approved-registry"
        return "public"

    def stage_to_quarantine(self, artifact: Artifact) -> str:
        """Copy the artifact bytes into quarantine. Returns quarantine path."""
        src = Path(artifact.manifest_path)
        dest = Path(settings.quarantine_dir) / f"{artifact.package.replace('/', '__')}@{artifact.version}.tgz"
        shutil.copyfile(src, dest)
        return str(dest)
