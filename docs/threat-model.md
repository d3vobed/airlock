# Threat Model — AIRLOCK

AIRLOCK only claims to stop a specific set of threats. Everything else is
explicitly out of scope. The table below records, per threat, whether AIRLOCK is
**prevented** (the pipeline blocks it), **mitigated** (significantly reduces
likelihood/impact), **detected** (records a decision + event after the fact), or
**out of scope**.

## Threats addressable by an admission layer

| # | Threat | AIRLOCK posture | Where |
|---|---|---|---|
| T1 | **Tampered artifact in transit** (bits changed between registry and build) | **Prevented** — exact-byte identity `airlock:sha256:<digest>`; expected-digest pinning; any byte change ⇒ REJECTED | `evidence` check, `verify` |
| T2 | **Dependency confusion** (public impostor squats an internal name) | **Prevented** — source is part of provenance; `public` source rejected; policy source must be `internal-approved-registry` | `source` check |
| T3 | **Typosquatting / name look-alikes** (e.g. `naijapay-payment-sdk`) | **Detected** — policy is name-exact; near-miss names are unknown ⇒ fail closed; an audit trail records the attempt | `policy` check |
| T4 | **Account takeover / publisher compromise** (approved publisher ships a malicious version) | **Prevented at the last line** — policy approves the *publisher*; the sandbox then runs the code and blocks malicious behavior; known-good (LKG) remains for rollback | `sandbox`, `fallback` |
| T5 | **Malicious lifecycle scripts** (`preinstall`/`install`/`postinstall`)** executed during build with build permissions** | **Prevented** — lifecycle scripts are identified before execution, executed only inside the isolated sandbox (`network:none`) or blocked outright; execution-by-build never happens unreviewed | `lifecycle`, `sandbox` |
| T6 | **Malicious behavior at install time** (network exfiltration, SSH, env theft, filesystem writes) | **Prevented** — sandbox blocks network/SSH/env/filesystem access and fails the artifact | `sandbox` |
| T7 | **Poisoned version bump** (upgrade day pulls a compromised upgrade) | **Prevented** — updates run the same pipeline; failure keeps the **LKG** available and recommends rollback | `fallback` |
| T8 | **Supply Chain Passport forgery / claiming verified-bytes** | **Prevented** — passport is bound to exact bytes; `verify_digest` recomputes; provenance `VERIFIED` only when a mechanism verified it | `passport` |
| T9 | **Fail-open sandbox** (no Docker ⇒ silently "pass") | **Prevented** — docker mode without a daemon is `failed`, not passed | `runner.docker_available` |

## Threats AIRLOCK mitigates but does not fully prevent

| Threat | Posture | Notes |
|---|---|---|
| Build-time code obfuscation / sleep-and-behave | **Detected** (sandbox observable) | The sandbox watches behavior; obfuscated long-delay malware is a known limitation |
| Dependency supply chain reasoning | **Mitigated** | Transitive graph is recorded, not exhaustively analyzed |
| Human error in policy authoring | **Mitigated** | Fail-closed default + CI checking of the matrix |
| Updates to committed npm fixtures offline | **Mitigated** | Fixtures are `airlock:sha256` pinned in `demo/digests.json` and SRI-checked |

## Explicitly out of scope (by design)

- Building a replacement npm/general registry or global mirror.
- Malware analysis / classification / AV.
- Software Composition Analysis / full SBOM platform.
- Continuous monitoring / SIEM / SOC dashboard.
- Runtime network defense after admission.

Staying out of those lanes keeps the demo honest: the *single job* is the
admission decision.

## The honest-passport rule

No check result, passport field, or event may claim more than what actually
happened:

- `provenance` ∈ {"verified", "unavailable", "failed"} — never guess `verified`.
- `sandbox.mode` ∈ {"docker", "simulate"} — the mode that actually ran.
- `integrity` ∈ verified / computed-only — "computed only" is not "verified".
- A REJECTED artifact never carries a passport claiming `TRUSTED`.

## Scoring significance

The engineering scorecard ([`engineering-scorecard.md`](engineering-scorecard.md))
maps each of these preventions to reproducible tests and a live demo, which is
the strongest evidence an admission layer can offer.