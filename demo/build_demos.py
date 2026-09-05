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

    digests_path = DEMO / "digests.json"
    digests_path.write_text(json.dumps(digests, indent=2) + "\n")
    print(f"wrote {digests_path.relative_to(DEMO.parent)}")

    assert digests["legitimate-package"] != digests["tampered-artifact"], (
        "tampered artifact must differ from legitimate artifact"
    )
    print("OK: tampered digest differs from legitimate digest")


if __name__ == "__main__":
    build()