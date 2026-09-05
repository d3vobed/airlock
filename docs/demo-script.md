# Demo Script — AIRLOCK

A reproducible, ~4-minute demo. Every step is offline-first except the live npm
step, which is optional.

## Prereqs

- `.venv` (`make setup`)
- Registry state reset (each run):

```bash
cd /home/obx/airlock
rm -f airlock.db
```

## A. CLI matrix (60s)

```bash
python -m apps.cli.airlock demo --clean
```

Table to present:

| # | Input | Expected | Why |
|---|---|---|---|
| 1 | `@naijapay/payment-sdk@2.1.0` (legit) | TRUSTED | every check passes |
| 2 | dependency-confusion impostor | REJECTED | source `public` |
| 3 | malicious package | REJECTED | sandbox suspicious |
| 4 | tampered artifact (1 bit) | REJECTED | digest mismatch |
| 5 | malicious update `2.1.1` | REJECTED, LKG `2.1.0` | rollback available |
| 6 | `is-number@7.0.0` (offline, real npm) | TRUSTED | SRI verified |

## B. Live npm (30s, network)

```bash
python -m apps.cli.airlock admit-npm "is-number@7.0.0" --npm-mode live
```

Point out: the tarball is resolved from `registry.npmjs.org`, downloaded to
exactly one source of bytes, and the **SRI `sha512` from registry metadata must
match before admission**. Also show `REUSE ✓` when the digest equals the
offline fixture — proof that identity is bytes, not the name.

## C. Controlled canary (the "we published this" moment)

```bash
python -m apps.cli.airlock admit-npm "@airlock-demo/canary-sdk@1.0.0" --npm-mode offline
# → TRUSTED, lifecycle: postinstall (reported, not executed outside sandbox)

python -m apps.cli.airlock admit-npm "@airlock-demo/canary-sdk@1.0.1" --npm-mode offline --malicious
# → REJECTED, sandbox suspicious; LKG 1.0.0 remains
```

Narrate: *this is a package YOUR org publishes. 1.0.0 is clean. 1.0.1 carries a
malicious install workflow. Same publisher, same name — only the sandbox stages
it out. That is the entropy that name-and-version can't give you.*

Source of the canary: `demo/controlled-npm-package/` (publishable).

## D. API + UI (60s)

```bash
make run-api        # :8000
make run-frontend   # :3000
```

In the UI:
1. Health badge green (`gateway online`).
2. Click **Legitimate package** → decision card with all checks.
3. Click **Malicious package** → REJECTED card, sandbox `simulate` recorded.
4. Click **Team-controlled npm violation** → REJECTED, LKG shown.
5. Scroll to ledger → click **rollback** on a rejected artifact → LKG message.
6. Highlight a passport: exact `airlock:sha256:…` bytes bound.

## E. Honesty check line

End with the one line that differentiates AIRLOCK:

> Every artifact got one of two outcomes — ADMIT or REJECT — and every passport
> records exactly what was verified, in exactly what sandbox mode. We don't ship
> a claim we can't prove.

## Troubleshooting

- `ValueError: package not found` → wrong offline fixture name; check
  `npm_cache/fixtures/`. Live mode needs network.
- `sandbox failed: no Docker` → you requested `docker` mode; use `--sandbox
  simulate` or install Docker.
- UI shows `gateway offline` → gateway not running on `:8000`, or
  `NEXT_PUBLIC_API_BASE` points elsewhere.