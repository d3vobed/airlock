# AIRLOCK — Team C Frontend Notes

Kept from the C1/C2 PR review (bangiskhan) so the fixes are traceable.

## Bugs found + fixed (merged via PR #39)
- `app/layout.tsx` never imported `globals.css` → styles never reached the
  browser → added `import "./globals.css"`.
- The passport panel read `passport.sandbox.ok`, a field that does not exist on
  the backend `Passport` record. The real contract is `sandbox_status`
  (`passed`/`failed`/`skipped`) plus `sandbox.mode`/`network`/`secrets`/
  `filesystem`. `frontend/lib/api.ts` now models both, and the panel renders
  clean/blocked from `sandbox_status`.
- `/artifacts/rollback/{package}` could not match scoped names like
  `@airlock-demo/canary-sdk` (slashes). Route changed to
  `{package:path}` in `apps/gateway/routes/promote.py`.

## Notes on the blocking CI issue (not a frontend bug)
PR #39's CI was red because of a pre-existing Docker sandbox false positive
(`/home` and `/etc/ssh` exist in `node:20-alpine`, so the probe's own existence
checks flagged every real-container run as suspicious). Fixed in
`apps/sandbox/runner.py` — credential discovery is restricted to `~/.ssh` and
`/root/.ssh`. A clean sandbox now reports `passed`.

## Minor cleanup applied on merge
- Removed accidentally committed junk from the repo root: `ls`, `omo.txt`.
- Dropped the duplicate `frontend/postcss.config.mjs`; the existing
  `frontend/postcss.config.js` is the single Tailwind config (identical
  plugins).