"""Real npm registry resolver.

Resolves a package spec (``name@version``) against the actual npm registry,
retrieves registry metadata, identifies the exact tarball URL, downloads the
EXACT artifact bytes, and records everything needed for admission.

Two operating modes (exactly as documented in README):

  offline (default deterministic testbed)
      Uses committed/cached fixtures (npm_cache/fixtures/). No network.
      Recorded registry metadata (dist.tarball, dist.integrity) is replayed.

  live
      Real network resolution against registry.npmjs.org (or AIRLOCK_NPM_REGISTRY).
      Requires network. Used by ``make test-live-npm`` and explicit ``--npm-live``.

The exact bytes downloaded/resolved are the bytes AIRLOCK evaluates — there is
no second download for the sandbox. The artifact is cached so a later admit of
the same name@version reuses the exact identical tarball (with a digest check
against the recorded digest).

Never treat ``name@version`` as identity: identity is airlock:sha256:<digest>.
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.hashing.sha256 import sha256_file

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
NPM_CACHE_DEFAULT = REPO_ROOT / "npm_cache"


@dataclass
class NpmResolution:
    ecosystem: str = "npm"
    package: str = ""
    version: str = ""
    registry: str = "npm"
    registry_url: str = "https://registry.npmjs.org"
    tarball_url: str = ""
    npm_integrity: str = ""
    publisher: str | None = None
    dependencies: dict = field(default_factory=dict)
    lifecycle_scripts: dict = field(default_factory=dict)
    dist_tags: dict = field(default_factory=dict)
    digest: str = ""
    local_path: str = ""
    sha1: str = ""
    integrity_verified: bool = False
    mode: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_spec(spec: str) -> tuple[str, str]:
    """Parse ``name@version`` (scoped names supported) into (name, version)."""
    spec = spec.strip()
    if spec.startswith("@"):
        # scoped: @scope/name@version
        try:
            scope, rest = spec.split("/", 1)
            rest, _, version = rest.rpartition("@")
        except ValueError:
            raise ValueError(f"invalid scoped npm spec '{spec}'")
        name = f"{scope}/{rest}"
    else:
        if "@" in spec:
            name, version = spec.rsplit("@", 1)
        else:
            name, version = spec, ""
    if not name or not version:
        raise ValueError(f"invalid npm spec '{spec}' — expected name@version")
    return name, version


def _request_json(url: str, timeout: int = 30) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _download(url: str, dest: Path, timeout: int = 60) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=timeout) as resp, open(dest, "wb") as fh:
        fh.write(resp.read())


def verify_sha512_sri(path: str | Path, integrity: str) -> bool:
    """Verify npm's Subresource-Integrity value (sha512-<base64>) against bytes."""
    if not integrity or not integrity.startswith("sha512-"):
        return False
    expected_b64 = integrity.split("-", 1)[1]
    h = hashlib.sha512()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    actual = base64.standard_b64encode(h.digest()).decode("ascii")
    return actual == expected_b64


class NpmResolver:
    """Resolves npm specs to exact cached artifacts with full registry metadata."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or NPM_CACHE_DEFAULT
        self.fixtures_dir = self.cache_dir / "fixtures"
        self.meta_dir = self.cache_dir / "metadata"
        self.fixtures_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def resolve(self, spec: str, mode: str = "offline", registry: str | None = None) -> NpmResolution:
        """Resolve ``name@version`` to an exact, cached, verified artifact.

        mode: 'offline' (fixtures only, no network), 'live' (real registry),
              'auto' (fixture first, else live).
        """
        mode = mode.lower() if mode else "auto"
        if mode not in ("offline", "live", "auto"):
            raise ValueError(f"unknown npm mode '{mode}'")

        name, version = parse_spec(spec)

        if mode in ("offline", "auto"):
            cached = self._load_fixture(name, version)
            if cached is not None:
                return cached

        if mode in ("live", "auto"):
            resolved = self._resolve_live(name, version, registry=registry or "https://registry.npmjs.org")
            self._save_fixture(resolved)
            return resolved

        raise RuntimeError(
            f"npm resolution '{spec}' requires live mode (no offline fixture available) "
            "— run `make test-live-npm` or download it first"
        )

    # ------------------------------------------------------------------ #
    # Fixture (offline) path
    # ------------------------------------------------------------------ #
    def fixture_path(self, name: str, version: str) -> Path:
        slug = f"{name.replace('/', '__')}@{version}"
        return self.fixtures_dir / f"{slug}.tgz"

    def meta_path(self, name: str, version: str) -> Path:
        slug = f"{name.replace('/', '__')}@{version}"
        return self.meta_dir / f"{slug}.json"

    def _load_fixture(self, name: str, version: str) -> NpmResolution | None:
        tgz = self.fixture_path(name, version)
        meta = self.meta_path(name, version)
        if not tgz.exists() or not meta.exists():
            return None
        data = json.loads(meta.read_text())
        # Recompute the digest of the exact cached bytes to guard fixture drift.
        data["digest"] = sha256_file(tgz)
        data["local_path"] = str(tgz)
        data["mode"] = "offline-cached"
        return NpmResolution(**data)

    def _save_fixture(self, r: NpmResolution) -> None:
        (self.meta_dir / f"{r.package.replace('/', '__')}@{r.version}.json").write_text(
            json.dumps({k: v for k, v in r.to_dict().items() if k not in ("digest", "local_path", "mode")}, indent=2)
        )

    # ------------------------------------------------------------------ #
    # Live (registry) path
    # ------------------------------------------------------------------ #
    def _resolve_live(self, name: str, version: str, registry: str) -> NpmResolution:
        encoded = name.replace("/", "%2F")
        try:
            doc = _request_json(f"{registry}/{encoded}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise ValueError(f"package '{name}' not found on registry {registry}")
            raise RuntimeError(f"registry error {e.code} for '{name}': {e.reason}")
        except (urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"cannot reach registry {registry}: {e}")
        versions = doc.get("versions", {})
        if version not in versions:
            raise ValueError(f"version {version} not found for {name}")
        ver = versions[version]
        dist = ver.get("dist", {})
        tarball_url = dist.get("tarball")
        if not tarball_url:
            raise ValueError(f"no tarball URL for {name}@{version}")

        dest = self.fixture_path(name, version)
        _download(tarball_url, dest)

        integrity = dist.get("integrity", "")
        sri_ok = verify_sha512_sri(dest, integrity) if integrity else False

        resolution = NpmResolution(
            package=name,
            version=version,
            registry="npm",
            registry_url=registry,
            tarball_url=tarball_url,
            npm_integrity=integrity,
            publisher=None,
            dependencies=ver.get("dependencies") or {},
            lifecycle_scripts=ver.get("scripts") or {},
            dist_tags={k: v for k, v in doc.get("dist-tags", {}).items()
                       if v == version or k == "latest"},
            digest=sha256_file(dest),
            local_path=str(dest),
            sha1=dist.get("shasum", ""),
            integrity_verified=sri_ok,
            mode="live",
        )
        return resolution

    # ------------------------------------------------------------------ #
    # Lifecycle analysis
    # ------------------------------------------------------------------ #
    LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare")

    @staticmethod
    def lifecycle_scripts(meta: dict | None) -> list[str]:
        """List npm lifecycle script keys present in package metadata."""
        if not meta:
            return []
        scripts = meta.get("scripts", {})
        return [k for k in NpmResolver.LIFECYCLE_KEYS if k in scripts]