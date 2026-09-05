# Component Contracts

AIRLOCK services communicate through plain dictionaries and pydantic models.
These contracts are the seams between components; every screen in the UI and
every command in the CLI consumes exactly the same shapes so parity is
enforced and testable.

## Artifact (core/models/artifact.py)

```python
Artifact(
    package: str,                 # e.g. "@naijapay/payment-sdk"
    version: str,                 # e.g. "2.1.0"
    source: str,                  # e.g. "internal-approved-registry" | "public"
    publisher: str | None,
    digest: str,                  # hex sha256 of the artifact bytes
    artifact_id: str = "airlock:sha256:<digest>",
    ecosystem: str = "generic",   # "npm" | "generic"
    registry: str | None = None,  # "npm" | "internal-approved-registry"
    tarball_url: str | None = None,
    npm_integrity: str | None = None,   # "sha512-..."
    lifecycle_scripts: list[str] = [],  # preinstall/install/postinstall/prepare
    dependencies: dict[str, str] = {},
    observations: dict = {},
    manifest_path: str | None = None,
    state: ArtifactState = RESOLVED,
)
```

## Admission result (dict)

Every admission call (`AdmissionPipeline.admit`, `admit_npm`, and each REST
route) returns a single dict:

```python
{
  "artifact_id", "package", "version", "digest", "source",
  "state": ArtifactState,       # e.g. BUILDABLE / REJECTED
  "decision": "TRUSTED"|"REJECTED",
  "reason": str | None,
  "checks": [ {"name", "status", "detail"}, ... ],   # one per pipeline stage
  "sandbox": {"mode": "docker"|"simulate", "ok": bool, "events": [...]},
  "lkg": {"version": str} | None,
  "passport": { ...Supply Chain Passport dict... },
  "timestamp": iso8601,
  "registry": str | None, "tarball_url": str | None,
}
```

## Supply Chain Passport (core/models/passport.py)

```python
Passport(
    artifact_id: str,   # airlock:sha256:<hex>
    package: str, version: str,
    digest: str,        # hex sha256 (must equal sha256 of file at verify time)
    source: str,
    decision: "TRUSTED"|"REJECTED",
    status: "TRUSTED"|"REJECTED",
    checks: [ {"name", "status", "detail"} ],
    sandbox: {"mode": "docker"|"simulate", "ok": bool},
    provenance: "verified"|"unavailable"|"failed",   # honest, never guessed
    timestamp: iso8601,
)
```

`verify_digest(passport, computed_digest) == (artifact_id(computed_digest)
== passport.artifact_id)`. A single flipped bit ⇒ False.

## Policy engine (apps/gateway/services/policy.py)

`PolicyEngine(policy_file).evaluate(artifact) -> PolicyResult(passed: bool,
failures: list[str])`. Faithful decoding:

- `publisher: null` ⇒ schema recognizes invisible nulls (YAML 1.1) AND decoded
  `None`; both treated as "no publisher constraint", never a false "allowed".
- Unknown package ⇒ `failures = ["...no policy rule..."]`, `passed=False`.
- Source must equal the rule's `source`; version pinning enforced.

## Sandbox service (apps/gateway/services/sandbox.py)

`SandboxService(mode).execute(workspace, artifact) ->
(result: SandboxResult, effective_mode: str, status: SandboxStatus)`

```python
SandboxResult(ok: bool, suspicious: bool, events: list,
              stdout: str, stderr: str, error: str | None,
              blocked_attempts: list[{"kind", "detail"}])
```

- `mode="docker"` + `docker_available() == False` ⇒ `ok=False`, status failed,
  error mentions "Docker unavailable" (fail closed).
- `mode="simulate"` (or `auto` fallback) ⇒ deterministic simulation, no
  container required, and the returned `effective_mode` is truthful.

## npm resolver (apps/gateway/services/npm_resolver.py)

`NpmResolver().resolve(spec, mode) -> NpmResolution`
`NpmResolution(package, version, local_path, digest, npm_integrity, mode,
dependencies, tarball_url, registry, ok, error)`

- `spec` must be `name@version` (scoped `@scope/name@version` supported).
- `mode=offline` → only `npm_cache/fixtures/`; no network.
- `mode=live` → resolve from registry.npmjs.org, download to a single local
  file (single source of bytes), verify `sha512` SRI before any use.

## Storage (apps/gateway/store.py)

SQLite tables: `artifacts`, `passports`, `decisions`, `lkg`, `events`.
`Storage()` defaults to `settings.db_path` so tests and CLI share isolation via
the frozen settings object.

## Fallback (apps/gateway/services/fallback.py)

```python
get_lkg(package) -> {"package","version","digest"} | None
rollback(package) -> {"package","version","available": True} | None
```

`rollback` is a **recommendation**, never an automatic promotion.