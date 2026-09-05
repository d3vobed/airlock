# Engineering Scorecard

How AIRLOCK maps to the ICSC 2026 Track G rubric. The framing: **real
engineering, not a mock**.

## 1. Functional completeness (working event, clean transition)

| Requirement | Evidence |
|---|---|
| Proven working code | 48 offline tests + docker-gated tests; matrix verified in this repo (see README) |
| Clean event transition | Admission pipeline yields deterministic `TRUSTED`/`REJECTED`; LKG survives a rejected update |
| Valuable to participants | Admission decisions, passports, LKG rollback, audit trail; UI + CLI + API parity |

## 2. Working demo (visible, verifiable)

`make demo-clean` produces a table with 5 synthetic attacks + 2 real npm cases,
all from one command, offline. The live-npm step additionally resolves from the
real registry and SRI-verifies. See [`demo-script.md`](demo-script.md).

## 3. Real-world rationale

Nigeria angle: open-source default, privileged installs, cheap look-alikes,
and regulator questions. See [`nigeria-use-case.md`](nigeria-use-case.md).

## 4. Security principles

| Principle | Mechanism |
|---|---|
| Isolation of untrusted input | Docker `network:none` sandbox + simulate fallback |
| Least privilege | sandbox executes lifecycle, never the build |
| Fail closed | no daemon → failed; unknown policy → failed |
| Defense in depth | identity → integrity → SRI → lifecycle → source → policy → sandbox |
| Honest claims | provenance `UNAVAILABLE` unless verified; sandbox mode recorded |

## 5. Risk & mitigations

- Docker-less env → deterministic simulate (mode honestly labeled).
- Fixtures stale → `demo/digests.json` pins; SRI guard in resolver.
- Policy authoring error → CI matrix re-runs the scenario set.
- Live registry flake → offline fixtures keep `make test` network-free.

## 6. Scale (security topics)

Architecture doc + threat model cover identity vs names, tamper, dependency
confusion, typosquatting, compromised publishers, lifecycle scripts,
install-time exfiltration, poisoned upgrades, passport forgery, fail-open
avoidance. 10+ distinct topics, each tied to a mechanical check or test.

## 7. Business & product sense

- Honest passport = auditable provenance (a real ask from Nigerian fintech +
  regulators).
- LKG rollback = availability property, not just security.
- Canary package = org-control tooling story, extendable to UAT/promotion.

## 8. Professional engineering practice

| Practice | Evidence |
|---|---|
| VCS hygiene | Conventional commits, CI-approved `main`, gitignore, LICENSE |
| Reproducibility | `make setup && make test`; offline-first; Dockerfile/compose |
| Documentation | README, architecture, threats, contracts, demo script, SECURITY, CONTRIBUTING |
| Test discipline | offline default; `live`/`docker` marked explicitly |
| Issue tracking | GitHub epics/milestones/labels with A/B/C ownership (see issues) |
| Honesty over hype | sandbox mode, provenance, and integrity claims are never exaggerated |

## Quick self-audit checklist (run on main)

```bash
make test && make test-live-npm      # network variant
python -m apps.cli.airlock demo --clean
```

Both must be green before the presentation.