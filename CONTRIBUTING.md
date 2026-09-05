# Contributing

Thanks for helping harden AIRLOCK. This document describes how to work on the
codebase, run tests, and get your change merged.

## Ground rules

1. **Never merge a failing test.** CI is green on `main`.
2. **Never loosen a security control** without a written rationale and a test
   that proves the new behavior is correct.
3. **Exact bytes matter.** Anything that changes artifact identity must be
   reviewed through the lens of `airlock:sha256:<digest>`.
4. **Passports must be honest.** No field may claim `VERIFIED` unless a real
   mechanism verified it.

## Project layout

- `core/` — models, hashing, passwords/passports, declarative policy
- `apps/gateway/` — FastAPI gateway, admission pipeline, npm resolver
- `apps/sandbox/` — Docker/simulate isolation runner
- `apps/cli/` — the `airlock` CLI
- `demo/` — deterministic demo artifacts
- `npm_cache/fixtures/` — real offline npm fixtures (committed)
- `frontend/` — Next.js/TypeScript/Tailwind control UI
- `docs/` — architecture, threats, demo script, contracts

## Development loop

```bash
make setup         # venv + dependencies
make test          # offline test suite (uses committed fixtures)
make run-api       # gateway on :8000
make run-frontend  # UI on :3000
```

To exercise real-registry resolution:

```bash
make test-live-npm   # pytest incl. live-marked tests (needs network)
```

## Tests

- pytest; either `pytest.ini` markers:
  - `live` — requires network to registry.npmjs.org
  - `docker` — requires a working Docker daemon
- New security behavior **must** ship with a test in `tests/`.

## Commits

- Linear history on `develop`, fast-forward to `main`.
- Conventional messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
- Reference the issue: `feat(npm): pin tarball fetch to single source #12`.

## Branch protection

`main` requires at least one approving review and green CI. Direct pushes to
`main` are disabled; work in feature branches off `develop`.

## Reporting issues

Use the engineering-centric issue template: label `epic`/`enhancement`, fill
acceptance criteria, and link the milestone. Security issues go through
`SECURITY.md`.