"""AIRLOCK command-line interface.

Usage:
  airlock admit <artifact.tgz> [--source <src>] [--sandbox <mode>] [--malicious]
  airlock verify <artifact.tgz> <expected-sha256>
  airlock passport <artifact-id>
  airlock promote <artifact-id>
  airlock rollback <package-name>
  airlock demo

The CLI is server-free: it drives the admission pipeline directly. Use the
HTTP API when you want the web UI / shared store.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apps.gateway.deps import app_state
from apps.gateway.services.admission import AdmissionPipeline

PIPE_DEMO = """
EXTERNAL ARTIFACT
        ↓
      AIRLOCK
        ↓
  IDENTITY · INTEGRITY · SOURCE · POLICY · SANDBOX
        ↓
     TRUST / REJECT
        ↓
  TRUSTED INTERNAL ARTIFACT
"""


def _print(msg: str = "") -> None:
    print(msg)


def cmd_admit(args) -> None:
    if not Path(args.artifact).exists():
        _print(f"[ERROR] artifact not found: {args.artifact}")
        sys.exit(1)

    _print(f"AIRLOCK admission — {args.artifact}\n")
    pipeline = AdmissionPipeline(sandbox_mode=args.sandbox, malicious=args.malicious)
    result = pipeline.admit(args.artifact, source=args.source)

    _print(_table_checks(result["checks"]))
    _print(f"\nDECISION: {result['decision']}")
    if result.get("reason"):
        _print(f"REASON: {result['reason']}")
    if result.get("lkg") and result["lkg"].get("available"):
        _print(f"LAST KNOWN GOOD: {result['lkg']['package']}@{result['lkg']['version']} (available)")
    _print(f"\nARTIFACT ID: {result['artifact_id']}")
    if args.json:
        _print(json.dumps(result, indent=2, default=str))


def cmd_admit_npm(args) -> None:
    _print(f"AIRLOCK npm admission — {args.spec} (mode={args.npm_mode})\n")
    pipeline = AdmissionPipeline(sandbox_mode=args.sandbox, malicious=args.malicious)
    result = pipeline.admit_npm(args.spec, npm_mode=args.npm_mode, source="internal-approved-registry")

    _print(_table_checks(result["checks"]))
    _print(f"\nECOSYSTEM: npm   REGISTRY: {result.get('registry')}")
    _print(f"TARBALL: {result.get('tarball_url')}")
    if result["passport"].get("npm_integrity"):
        _print(f"NPM SRI: {result['passport']['npm_integrity']}")
    _print(f"\nDECISION: {result['decision']}")
    if result.get("reason"):
        _print(f"REASON: {result['reason']}")
    _print(f"\nARTIFACT ID: {result['artifact_id']}")
    if args.json:
        _print(json.dumps(result, indent=2, default=str))


def _table_checks(checks: list[dict]) -> str:
    lines = []
    markers = {"passed": "✓", "failed": "✗", "verified": "✓", "unavailable": "?", "skipped": "–", "failed'": "✗"}
    for c in checks:
        mark = markers.get(c.get("status", ""), "?")
        lines.append(f"  {mark} {c['name'].upper():10} {c.get('detail', '')}")
    return "\n".join(lines)


def cmd_verify(args) -> None:
    from core.hashing.sha256 import sha256_file

    if not Path(args.artifact).exists():
        _print(f"[ERROR] artifact not found: {args.artifact}")
        sys.exit(1)
    computed = sha256_file(args.artifact)
    _print(f"expected: {args.digest}")
    _print(f"computed: {computed}")
    matches = computed == args.digest.lower()
    _print(f"\nINTEGRITY: {'VERIFIED ✓' if matches else 'MISMATCH ✗'}")
    sys.exit(0 if matches else 1)


def cmd_passport(args) -> None:
    p = app_state.passport_svc.get(args.artifact_id)
    if not p:
        _print("[ERROR] passport not found")
        sys.exit(1)
    _print(json.dumps(p.model_dump(), indent=2, default=str))


def cmd_promote(args) -> None:
    from apps.gateway.routes.promote import promote as _promote

    result = _promote(args.artifact_id)
    _print(json.dumps(result, indent=2))


def cmd_rollback(args) -> None:
    result = app_state.fallback_svc.rollback(args.package)
    if not result:
        _print("[ERROR] no last known good artifact available")
        sys.exit(1)
    _print(json.dumps(result, indent=2))


def cmd_demo(args) -> None:
    _print(PIPE_DEMO)
    _print("=" * 60)
    if args.clean:
        reset_state()
        _print("[state] cleared registry + database for a deterministic demo\n")
    demo = DemoScript(sandbox_mode=args.sandbox)
    demo.run_all()


def reset_state() -> None:
    import shutil as _sh

    from apps.gateway.config import settings as _settings

    _settings.ensure_dirs()
    for d in (_settings.trusted_dir, _settings.quarantine_dir, _settings.rejected_dir, _settings.lkg_dir):
        for f in Path(d).iterdir():
            if f.name.startswith("_ws_") or f.suffix == ".tgz" or f.is_dir():
                if f.is_dir():
                    _sh.rmtree(f, ignore_errors=True)
                else:
                    f.unlink(missing_ok=True)
    db = Path(_settings.db_path)
    if db.exists():
        db.unlink()


class DemoScript:
    """Deterministic end-to-end demo mirroring docs/demo-script.md."""

    DEMO_DIR = Path(__file__).resolve().parent.parent.parent / "demo"

    def __init__(self, sandbox_mode: str | None = None):
        self.sandbox_mode = sandbox_mode

    def run_all(self) -> None:
        steps = [
            ("[1] Legitimate package", "legitimate-package/package.tgz", False, "internal-approved-registry", None),
            ("[2] Dependency confusion", "dependency-confusion/package.tgz", False, "public", None),
            ("[3] Malicious package", "malicious-package/package.tgz", True, "internal-approved-registry", None),
            ("[4] Tampered artifact", "tampered-artifact/package.tgz", False, "internal-approved-registry", "legitimate-package"),
        ]
        failures = 0
        for label, rel, malicious, source, pin_ref in steps:
            _print(f"\n{label}")
            path = self.DEMO_DIR / rel
            pipeline = AdmissionPipeline(sandbox_mode=self.sandbox_mode, malicious=malicious)
            try:
                expected_digest = None
                if pin_ref:
                    digests = json.loads((self.DEMO_DIR / "digests.json").read_text())
                    expected_digest = digests.get(pin_ref)
                result = pipeline.admit(str(path), source=source, expected_digest=expected_digest)
                _print(_table_checks(result["checks"]))
                _print(f"DECISION: {result['decision']}")
                if result.get("reason"):
                    _print(f"  REASON: {result['reason']}")
                ok = result["decision"] in ("TRUSTED", "REJECTED")
                if not ok:
                    failures += 1
            except Exception as e:  # noqa: BLE001
                _print(f"  ERROR: {e}")
                failures += 1

        _print("\n[5] Malicious update → REJECTED → LKG fallback")
        # Step 5a: admit trusted 2.1.0 (records LKG)
        pipeline = AdmissionPipeline(sandbox_mode=self.sandbox_mode, malicious=False)
        r1 = pipeline.admit(str(self.DEMO_DIR / "legitimate-package/package.tgz"), source="internal-approved-registry", expected_digest=self._digest("legitimate-package"))
        _print(f"  admit @2.1.0 → {r1['decision']}")
        # Step 5b: admit malicious 2.1.1 (rejected)
        pipeline2 = AdmissionPipeline(sandbox_mode=self.sandbox_mode, malicious=True)
        r2 = pipeline2.admit(str(self.DEMO_DIR / "malicious-update/package.tgz"), source="internal-approved-registry")
        _print(f"  admit @2.1.1 → {r2['decision']}")
        # Step 5c: LKG fallback
        lkg = app_state.fallback_svc.get_lkg("@naijapay/payment-sdk")
        _print(f"  LAST KNOWN GOOD → @{(lkg or {}).get('version', 'NONE')} (available)")

        _print("\n")
        _print("=" * 60)
        _print("AIRLOCK DEMONSTRATION COMPLETE")
        if failures:
            sys.exit(1)

    def _digest(self, name: str) -> str | None:
        try:
            digests = json.loads((self.DEMO_DIR / "digests.json").read_text())
            return digests.get(name)
        except FileNotFoundError:
            return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="airlock", description=PIPE_DEMO)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("admit", help="Admit an artifact tarball")
    sp.add_argument("artifact")
    sp.add_argument("--source", default=None)
    sp.add_argument("--sandbox", default="auto", choices=["auto", "docker", "simulate"])
    sp.add_argument("--malicious", action="store_true", help="demo: treat as malicious for sandbox simulation")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_admit)

    sp = sub.add_parser("admit-npm", help="Admit a real npm package (name@version)")
    sp.add_argument("spec")
    sp.add_argument("--npm-mode", default="auto", choices=["offline", "live", "auto"])
    sp.add_argument("--sandbox", default="auto", choices=["auto", "docker", "simulate"])
    sp.add_argument("--malicious", action="store_true", help="demo: treat as malicious for sandbox simulation")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_admit_npm)

    sp = sub.add_parser("verify", help="Verify an artifact digest")
    sp.add_argument("artifact")
    sp.add_argument("digest")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("passport", help="Show an artifact's Supply Chain Passport")
    sp.add_argument("artifact_id")
    sp.set_defaults(func=cmd_passport)

    sp = sub.add_parser("promote", help="Promote an artifact to trusted")
    sp.add_argument("artifact_id")
    sp.set_defaults(func=cmd_promote)

    sp = sub.add_parser("rollback", help="Show Last Known Good for a package")
    sp.add_argument("package")
    sp.set_defaults(func=cmd_rollback)

    sp = sub.add_parser("demo", help="Run the deterministic demonstration")
    sp.add_argument("--sandbox", default="auto", choices=["auto", "docker", "simulate"])
    sp.add_argument("--clean", action="store_true", help="reset registry + database before running")
    sp.set_defaults(func=cmd_demo)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        _print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()