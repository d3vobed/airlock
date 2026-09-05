# Nigeria Use Case — Why an Admission Layer Matters Now

## The problem

Nigeria's developer ecosystem is one of the fastest-growing in the world, and
the national context makes the software supply chain a *first-order* risk:

1. **Open source is the default.** Nigerian startups, fintechs, and the public
   sector build on npm and other registries because there isn't a domestic
   mirror or a national trust model yet.
2. **Dependencies run with full privileges.** A malicious `postinstall` runs
   inside the CI of a fintech with production secrets — exactly when a breach
   is most expensive.
3. **Look-alikes are cheap to mint.** A package named for a well-known bank or
   payment rail (`naijapay-payment-sdk` vs `@naijapay/payment-sdk`) costs
   nothing to publish, and a single wrong import during an incident is all it
   takes.
4. **Regulators are starting to ask why.** Financial institutions adopting
   open source need a *technical* answer to "how do you know the code that
   reached production is the code that was approved?"

## What AIRLOCK gives a Nigerian organization

- **A single gate** between the internet and the trusted build chain. Energy is
  spent *once*, at admission.
- **Supply Chain Passports** per artifact: exact bytes, source, decision, and
  sandbox result. This is exactly the artifact provenance an auditor or a
  regulator can verify.
- **Last Known Good rollback** so a botched (or poisoned) upgrade isn't a
  multi-hour outage.
- **Honest claims.** If we can't isolate the artifact (no Docker), the passport
  says `simulate` — it never fabricates DV.

## Worked example (with our demo data)

A Lagos fintech internalizes its payment SDK as `@naijapay/payment-sdk`:

1. Developer runs `npm i @naijapay/loyalty-sdk`. That package is approved by
   policy (same publisher `naijapay`).
2. A *public* package named `@naijapay/payment-sdk` exists on the public
   registry. AIRLOCK's source check rejects any artifact not arriving from
   `internal-approved-registry` → **dependency confusion stopped**.
3. The approved publisher's account is compromised and a new `2.1.1` watches
   for envs and opens SSH. AIRLOCK's sandbox blocks the install-time behavior
   → **REJECTED**, LKG `2.1.0` stays available.
4. A byte of `2.1.0` is flipped in transit. Digest check fails →
   **REJECTED before execution**.

None of these four cases required a rules engine about *intent*. Each is a
mechanical, testable property of the bytes and the environment.

## Scale-out

The same pattern extends to:
- **Fintech** (payment rails): approve tight subsets of publishers and versions.
- **Public sector** (digital identity, education platforms): admission + audit
  trail for every library in government builds.
- **Universities / CDTs**: a teaching admission layer that shows how the check
  works (the `simulate` sandbox is ideal for a classroom).

## Demo angle

The repo ships `@airlock-demo/canary-sdk` — a *you-control* package — so a live
demo can publish a benign `1.0.0`, admoit it as TRUSTED, then bump to `1.0.1`
carrying a demonstration malicious workflow and watch AIRLOCK REJECT it while
LKG `1.0.0` remains available. Full script: [`demo-script.md`](demo-script.md).