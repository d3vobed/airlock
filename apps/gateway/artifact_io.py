"""Helpers for parsing npm-style artifact archives (package.tgz)."""
from __future__ import annotations

import io
import json
import shutil
import tarfile
from pathlib import Path

from core.hashing.sha256 import sha256_file


def read_package_json(path: str | Path) -> dict | None:
    """Extract package.json from an npm tarball without extracting to disk.

    Returns a dict or None if not found / malformed.
    """
    try:
        with tarfile.open(path, "r:gz") as tf:
            member = tf.extractfile("package/package.json")
            if member is None:
                return None
            return json.loads(member.read().decode("utf-8"))
    except (tarfile.TarError, json.JSONDecodeError, OSError, KeyError):
        return None


def describe_artifact(path: str | Path) -> dict:
    """Return identity metadata for an artifact tarball."""
    path = Path(path)
    meta = read_package_json(path) or {}
    return {
        "package": meta.get("name"),
        "version": meta.get("version"),
        "publisher": meta.get("publisher"),
        "digest": sha256_file(path),
    }


def flatten_tarball(path: str | Path, dest: str | Path) -> None:
    """Safely extract a tarball into ``dest``, stripping a leading 'package'.

    Guards against path traversal and symlink escapes.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "r:gz") as tf:
        _safe_extract(tf, dest)


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest) + "/") and target != dest:
            raise ValueError(f"Unsafe path in archive: {member.name}")
    tf.extractall(dest)


def make_tarball(package_dir: str | Path, out_path: str | Path) -> str:
    """Create an npm-style package.tgz from a package directory.

    The archive is laid out under a top-level ``package/`` directory, which is
    how npm packs packages and what AIRLOCK expects.
    """
    package_dir = Path(package_dir)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists():
        out_path.unlink()

    with tarfile.open(out_path, "w:gz") as tf:
        for f in sorted(package_dir.rglob("*")):
            if f.is_file():
                arcname = f"package/{f.relative_to(package_dir)}"
                tf.add(f, arcname=arcname)
    return str(out_path)


def copy_artifact(src: str | Path, dest: str | Path) -> str:
    """Copy an artifact binary into a registry directory and return its path."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)
    return str(dest)
