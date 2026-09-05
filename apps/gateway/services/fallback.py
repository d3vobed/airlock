"""Last Known Good (LKG) fallback.

When a new version of a trusted package is rejected, the system keeps the most
recent trusted version available for rollback. A rejected update MUST never
replace the trusted artifact or the LKG entry.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from core.models.artifact import Artifact, ArtifactState

from ..config import settings
from ..store import Storage


class FallbackService:
    """Manages the Last Known Good artifact for each trusted package."""

    def __init__(self, storage: Storage):
        self.storage = storage

    def record_lkg(self, artifact: Artifact) -> None:
        """Record a trusted artifact as LKG and store a copy for fallback."""
        self.storage.save_lkg(
            artifact.package, artifact.version, artifact.artifact_id, artifact.digest
        )
        lkg_path = Path(settings.lkg_dir) / f"{artifact.package.replace('/', '__')}@{artifact.version}.tgz"
        src = Path(artifact.manifest_path)
        if src.exists() and not lkg_path.exists():
            shutil.copyfile(src, lkg_path)

    def get_lkg(self, package: str) -> dict | None:
        return self.storage.get_lkg(package)

    def rollback(self, package: str) -> dict | None:
        """Return the last known good artifact for a package, if any.

        Does not mutate the current trusted state; it simply makes the LKG the
        recommended fallback. Promotion is a separate, explicit action.
        """
        lkg = self.storage.get_lkg(package)
        if not lkg:
            return None
        lkg_path = Path(settings.lkg_dir) / f"{package.replace('/', '__')}@{lkg['version']}.tgz"
        return {
            "package": package,
            "version": lkg["version"],
            "artifact_id": lkg["artifact_id"],
            "digest": lkg["digest"],
            "available": lkg_path.exists(),
            "path": str(lkg_path) if lkg_path.exists() else None,
        }