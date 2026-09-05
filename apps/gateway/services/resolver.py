"""Resolver / Fetcher.

Resolves an admission request into a concrete local artifact file and its
identity metadata. In the MVP, artifacts are supplied as local tarballs (or
copied from an approved local source directory). This service is the seam
where real registry fetchers (npm/PyPI) would be added later.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from core.hashing.sha256 import artifact_id, sha256_file
from core.models.artifact import Artifact, ArtifactState, SourceKind

from ..artifact_io import describe_artifact, read_package_json
from ..config import settings


class Resolver:
    """Resolves an admit request into a resolved Artifact record."""

    def __init__(self, approved_dir: str | None = None):
        self.approved_dir = Path(approved_dir) if approved_dir else None

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

    def _infer_source(self, path: Path, publisher: str | None) -> str:
        # If the artifact came from the local approved-registry staging area, mark
        # it as approved; otherwise it is treated as external/untrusted.
        if self.approved_dir and self.approved_dir in path.parents:
            return "internal-approved-registry"
        return "public"

    def stage_to_quarantine(self, artifact: Artifact) -> str:
        """Copy the artifact bytes into quarantine. Returns quarantine path."""
        src = Path(artifact.manifest_path)
        dest = Path(settings.quarantine_dir) / f"{artifact.package.replace('/', '__')}@{artifact.version}.tgz"
        shutil.copyfile(src, dest)
        return str(dest)
