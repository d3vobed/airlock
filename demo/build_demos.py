"""Build all demo artifacts (package.tgz) deterministically.

Creates:
  demo/legitimate-package/package.tgz   — @naijapay/payment-sdk@2.1.0 (trusted)
  demo/malicious-package/package.tgz    — synthetic attacker package (rejected)
  demo/dependency-confusion/package.tgz — impostor, same name, public source
  demo/malicious-update/package.tgz     — @naijapay/payment-sdk@2.1.1 (rejected)
  demo/tampered-artifact/package.tgz    — legitimate artifact with ONE byte flipped

Also writes demo/digests.json with original vs tampered digests.
"""
from __future__ import annotations

import json
from pathlib import Path

from apps.gateway.artifact_io import make_tarball
from core.hashing.sha256 import sha256_file

DEMO = Path(__file__).resolve().parent


def flip_byte(path: Path) -> bytes:
    """Change one byte of a file. Used to build the tampered artifact."""
    data = bytearray(bytearray(path.read_bytes())[:])
    data[10] ^= 0x01
    return bytes(data)


def build() -> None:
    targets = {
        "legitimate-package": ["package.json", "index.js", "install.js"],
        "malicious-package": ["package.json", "install.js"],
        "dependency-confusion": ["package.json", "install.js"],
        "malicious-update": ["package.json", "install.js"],
    }
    digests: dict[str, str] = {}

    for name, files in targets.items():
        srcdir = DEMO / name
        out = srcdir / "package.tgz"
        make_tarball(srcdir, out)
        digests[name] = sha256_file(out)
        print(f"built {out.relative_to(DEMO)}  sha256:{digests[name][:16]}…")

    # Tampered artifact = legitimate package with one byte flipped.
    legit = DEMO / "legitimate-package" / "package.tgz"
    tampered_dir = DEMO / "tampered-artifact"
    tampered_dir.mkdir(exist_ok=True)
    tampered = tampered_dir / "package.tgz"
    if not tampered.exists() or not (tampered_dir / "README.md").exists():
        tampered.write_bytes(flip_byte(legit))
    digests["tampered-artifact"] = sha256_file(tampered)
    print(f"built {tampered.relative_to(DEMO)}  sha256:{digests['tampered-artifact'][:16]}…")

    # Controlled npm canary package (also used as offline npm fixtures).
    npm_dir = DEMO / "controlled-npm-package"
    npm_fixtures = Path(npm_dir.parent.parent) / "npm_cache" / "fixtures"
    npm_fixtures.mkdir(parents=True, exist_ok=True)
    make_tarball(npm_dir, npm_fixtures / "@airlock-demo__canary-sdk@1.0.0.tgz")
    make_tarball(npm_dir / "version-1.0.1", npm_fixtures / "@airlock-demo__canary-sdk@1.0.1.tgz")
    digests["canary-1.0.0"] = sha256_file(npm_fixtures / "@airlock-demo__canary-sdk@1.0.0.tgz")
    digests["canary-1.0.1"] = sha256_file(npm_fixtures / "@airlock-demo__canary-sdk@1.0.1.tgz")
    print(f"built offline npm fixture @airlock-demo/canary-sdk@1.0.0 (sha256:{digests['canary-1.0.0'][:16]}…)")
    print(f"built offline npm fixture @airlock-demo/canary-sdk@1.0.1 (sha256:{digests['canary-1.0.1'][:16]}…)")

    digests_path = DEMO / "digests.json"
    digests_path.write_text(json.dumps(digests, indent=2) + "\n")
    print(f"wrote {digests_path.relative_to(DEMO.parent)}")

    assert digests["legitimate-package"] != digests["tampered-artifact"], (
        "tampered artifact must differ from legitimate artifact"
    )
    print("OK: tampered digest differs from legitimate digest")


if __name__ == "__main__":
    build()