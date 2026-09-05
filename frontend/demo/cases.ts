// Demo artifacts referenced by the UI. Paths are relative to the repo root,
// which is how the gateway resolve + admission expects them.
export interface DemoCase {
  id: string;
  label: string;
  description: string;
  kind: "tgz" | "npm";
  npm?: { spec: string; mode: "offline" | "live" | "auto" };
  path?: string;
  source?: string;
  malicious?: boolean;
  digest?: string;
}

export const DEMO_CASES: DemoCase[] = [
  {
    id: "legit",
    label: "Legitimate package (TRUSTED)",
    description:
      "@naijapay/payment-sdk@2.1.0 from an approved internal source passes every check and is trusted.",
    kind: "tgz",
    path: "demo/legitimate-package/package.tgz",
    source: "internal-approved-registry",
    digest: "7922a88a95a70d260d48b2759adcfc110eba4da25ad7f52e785b002f66d7bc5e",
  },
  {
    id: "confusion",
    label: "Dependency confusion (REJECTED)",
    description:
      "A public impostor named @naijapay/payment-sdk from an untrusted public source is rejected before download-into-build.",
    kind: "tgz",
    path: "demo/dependency-confusion/package.tgz",
    source: "public",
  },
  {
    id: "malicious",
    label: "Malicious package (REJECTED)",
    description:
      "A compromised approved package passes policy but is stopped at the sandbox for suspicious behavior.",
    kind: "tgz",
    path: "demo/malicious-package/package.tgz",
    source: "internal-approved-registry",
    malicious: true,
  },
  {
    id: "tampered",
    label: "Tampered artifact (REJECTED)",
    description:
      "A one-byte bit flip changes the artifact identity; the expected digest no longer matches.",
    kind: "tgz",
    path: "demo/tampered-artifact/package.tgz",
    source: "internal-approved-registry",
    digest: "d6ce85e08d4a306d679178aa5f5c8e4d3d87704a095163c313c12221191951dc",
  },
  {
    id: "update",
    label: "Malicious update 2.1.1 (REJECTED)",
    description:
      "A poisoned version bump is rejected and the Last Known Good 2.1.0 remains available for rollback.",
    kind: "tgz",
    path: "demo/malicious-update/package.tgz",
    source: "internal-approved-registry",
    malicious: true,
  },
  {
    id: "canary-benign",
    label: "Team-controlled npm package (TRUSTED)",
    description:
      "@airlock-demo/canary-sdk@1.0.0, a benign package you publish, resolves offline and is trusted with a reported postinstall.",
    kind: "npm",
    npm: { spec: "@airlock-demo/canary-sdk@1.0.0", mode: "offline" },
  },
  {
    id: "canary-violation",
    label: "Team-controlled npm violation (REJECTED)",
    description:
      "@airlock-demo/canary-sdk@1.0.1 carries a malicious install script and is stopped at the sandbox.",
    kind: "npm",
    npm: { spec: "@airlock-demo/canary-sdk@1.0.1", mode: "offline" },
    malicious: true,
  },
  {
    id: "is-number",
    label: "Real public npm package (TRUSTED, offline)",
    description:
      "The real is-number@7.0.0 resolved offline, SRI-verified against the committed fixture, trusted.",
    kind: "npm",
    npm: { spec: "is-number@7.0.0", mode: "offline" },
  },
];