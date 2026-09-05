# Security Policy

## Reporting a Vulnerability

AIRLOCK is an admission-control system; its security properties matter as much
as its feature behavior. If you find a vulnerability in AIRLOCK itself —
including the admission pipeline, the sandbox, the npm resolver, the gateway
API, or the frontend — please report it privately.

**Do not** open a public issue for a vulnerability.

- Email the maintainers via the repository owner (`d3vobed`) or open a
  [private security advisory](https://github.com/d3vobed/airlock/security/advisories/new).
- Include: affected version/commit, a minimum repro, and the impact you believe
  it has on an AIRLOCK deployment.

We aim to triage within 48h and to ship a fix as soon as a safe one exists.

## Scope

In scope:
- Fail-open / fail-closed behavior of `apps/gateway/services/admission.py`
- Sandbox escape or improper isolation in `apps/sandbox`
- Digest / SRI / provenance claims that can be forged in `core/`
- Authentication / authorization gaps in `apps/gateway/routes`
- Tampering of committed npm fixtures (`npm_cache/fixtures/`)

Out of scope:
- Vulnerabilities in third-party npm packages that AIRLOCK is *designed to stop*
- Phishing / social engineering

## Supported / security-relevant guarantees

- **Admit or reject**: no partial states; a failed check means `REJECTED`.
- **Fail closed**: sandbox errors (including "Docker unavailable") never produce
  a `TRUSTED` decision.
- **Exact bytes**: artifact identity is `airlock:sha256:<digest>`; any byte
  change invalidates the passport.
- **Honest passports**: provenance is never claimed `VERIFIED` when no
  mechanism can verify it.

## Disclosure

We will coordinate a fix and public disclosure following
[Coordinated Vulnerability Disclosure](https://github.com/SECURITY) practice.