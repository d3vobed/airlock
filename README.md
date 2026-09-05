# AIRLOCK — Supply Chain Admission Layer

**Admit or reject. Never silently promote. Fail closed.**

AIRLOCK is an admission-control layer that sits between external third-party
software and an organization's trusted build chain. Nothing enters the trusted
registry without passing identity, integrity, source, policy, and isolation
checks — and every decision mints a **Supply Chain Passport** that is bound to
the exact bytes of the artifact.

Built for the **ICSC 2026 Supply Chain Hackathon, Track G** with Nigeria's
developer ecosystem in mind (see [`docs/nigeria-use-case.md`](docs/nigeria-use-case.md)).

---

## Why

The modern software supply chain is broken for three structural reasons:

1. **Identity is a name, not bytes.** `name@version` collides with look-alike,
   squatting, and hijacked packages. AIRLOCK's identity is
   `airlock:sha256:<digest>` — the exact bytes.
2. **Download and build are the same step.** A malicious lifecycle script
   (`preinstall` / `install` / `postinstall`) executes *during* your build with
   your permissions. AIRLOCK separates verification from execution and runs the
   package in an isolated sandbox before it can ever reach a build.
3. **Nothing keeps a decision honest.** Fail-open pipelines claim "verified"
   without a mechanism. AIRLOCK fails closed and labels provenance `VERIFIED`
   only when a real mechanism proves it.

## What AIRLOCK does

| Check | What it stops |
|---|---|
| **identity** | tampered bits, swapped artifacts during transit |
| **integrity** | bytes changed after admission (expected digest pinning) |
| **npm integrity** | SRI (`sha512`) mismatch between registry metadata and downloaded tarball |
| **lifecycle** | hidden `preinstall`/`install`/`postinstall`/`prepare` scripts, flight-schedule analysis |
| **source** | dependency confusion, source spoofing, untrusted registries |
| **policy** | unapproved publishers, version pinning violations, scoped rules |
| **sandbox** | malicious/obfuscated install-time code, network/SSH/env exfiltration |
| **fallback (LKG)** | poisoned updates stay out while `@last-known-good` remains available |

## Quickstart

```bash
make setup                     # venv + deps
make test                      # offline test suite (real committed npm fixtures)
make run-api                   # gateway on :8000
make run-frontend              # UI on :3000
```

### CLI demo (full matrix, ~60s)

```bash
python -m apps.cli.airlock demo --clean      # resets state, runs all 6 scenarios
```

Expected outcome:

| Scenario | Decision |
|---|---|
| Legitimate `@naijapay/payment-sdk@2.1.0` | **TRUSTED** |
| Dependency confusion (public impostor) | **REJECTED** |
| Malicious package (passes policy, fails sandbox) | **REJECTED** |
| Tampered artifact (one byte flipped) | **REJECTED** |
| Malicious update `2.1.1` | **REJECTED** — LKG `2.1.0` available |
| Real npm package `is-number@7.0.0` (offline) | **TRUSTED** — SRI verified |

### Real npm admission

```bash
# offline: uses committed real fixtures (is-number@7.0.0, canary sdk)
python -m apps.cli.airlock admit-npm "is-number@7.0.0" --npm-mode offline

# live: resolves, downloads, and SRI-verifies from registry.npmjs.org
python -m apps.cli.airlock admit-npm "is-number@7.0.0" --npm-mode live
```

## Architecture

```
registry/packages ──► ┌───────────────────────────────────────────────┐
                      │  AIRLOCK GATEWAY  (:8000)                     │
npm (offline/live) ──►│  resolve → verify → policy → sandbox → fallback│──► TRUSTED
                      │        │            │        │          │      │     registry/
                      │        └──────► Passport (exact-byte bound)    │     trusted/
                      └───────────────────────────────────────────────┘
UI (Next.js :3000) ──►  decisions, passports, LKG, audit trail, demo selector
```

- `core/` — models, SHA-256 identity, passport, **declarative policy** (`core/policies/default.yaml`)
- `apps/gateway/` — FastAPI + admission pipeline + npm resolver
- `apps/sandbox/` — Docker isolation (`network:none`) with deterministic simulation fallback
- `demo/` — reproducible attack/defense scenarios
- `frontend/` — Next.js/TypeScript/Tailwind control pane

Full design: [`docs/architecture.md`](docs/architecture.md)
Threat model: [`docs/threat-model.md`](docs/threat-model.md)

## Security model

- **Admit or reject.** No partial trust, no gray states.
- **Fail closed.** Sandbox errors — including *"Docker unavailable"* — produce
  `REJECTED`, never `TRUSTED` ([`apps/sandbox/runner.py`](apps/sandbox/runner.py)). Docker mode with no daemon ⇒ check fails.
- **Exact bytes.** Artifact identity = `airlock:sha256:<digest>`. Passports are
  invalidated by a single bit flip.
- **Honest passports.** `provenance` is `VERIFIED` only when a verified
  mechanism exists; otherwise `UNAVAILABLE` / `FAILED`. Sandbox mode
  (`simulate` vs `docker`) is recorded truthfully on every passport.
- **CLI + API + UI parity.** All admission paths converge on the same pipeline
  so the demo never lies about what the product would do.

See [`SECURITY.md`](SECURITY.md) for responsible disclosure.

## Sandbox modes

| Mode | Behavior | Requirement |
|---|---|---|
| `auto` | Docker if available, else deterministic simulation | Docker daemon |
| `docker` | Real container, `network:none`, `npm install`, lifecycle execution | Docker daemon |
| `simulate` | Deterministic offline simulation (embedding-friendly) | none |

The **docker** path runs the real `npm install` inside a container with no
network; lifecycle-script behavior is captured. When Docker is unavailable the
pipeline **fails closed** rather than degrading to an unverified pass.
Unverified environments run `--sandbox simulate` and every passport says so.

## Tests

```bash
make test              # offline (48 tests, real committed npm fixtures)
make test-live-npm     # + live-registry resolution (network)
pytest -m docker       # real Docker sandbox (requires daemon)
```

## Project layout

```
apps/cli/                CLI (admit, admit-npm, verify, passport, promote, rollback, demo)
apps/gateway/            FastAPI gateway + admission pipeline + npm resolver
apps/sandbox/            Docker/simulate isolation runner
core/models/             artifact, decision, passport
core/policies/           declarative policy rules
npm_cache/fixtures/      real committed npm artifacts (offline)
demo/                    reproducible demo scenarios (synthetic + 1 real npm package)
frontend/                Next.js control UI
tests/                   pytest suite (offline-first; live/docker gated)
docs/                    architecture, threats, Nigeria use case, demo script
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Engineering strategy

Track G emphasizes real engineering. The [`docs/engineering-scorecard.md`](docs/engineering-scorecard.md)
maps AIRLOCK to that rubric, and `docs/contracts.md` defines the component
contracts behind the admission pipeline.