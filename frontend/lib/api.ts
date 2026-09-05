// Frontend gateway base. Override with NEXT_PUBLIC_API_BASE if the gateway
// runs elsewhere (e.g. 0.0.0.0). Defaults to localhost:8000 (docker-compose/Makefile).
const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export interface AdmissionResponse {
  artifact_id: string;
  package: string;
  version: string;
  digest: string;
  source: string;
  state: string;
  decision: string;
  reason: string | null;
  checks: { name: string; status: string; detail: string }[];
  sandbox: { mode: string; ok: boolean; events?: unknown[] };
  lkg: { version: string } | null;
  passport: Record<string, unknown>;
  timestamp: string;
  registry?: string | null;
  tarball_url?: string | null;
}

export interface ArtifactRecord {
  artifact_id: string;
  package: string;
  version: string;
  source: string;
  digest: string;
  state: string;
  reason: string | null;
  created_at: string;
}

export interface EventRecord {
  artifact_id: string;
  package: string;
  version: string;
  decision: string;
  reason: string | null;
  created_at: string;
}

export interface Health {
  status: string;
  service: string;
  db: string;
}

export interface PassportRecord {
  artifact_id: string;
  package: string;
  version: string;
  digest: string;
  source: string;
  decision: string;
  status: string;
  timestamp: string;
  provenance?: string;
  sandbox?: { mode?: string; ok?: boolean };
  checks?: { name: string; status: string; detail: string }[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail || detail;
    } catch {
      /* keep statusText */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<Health>("/health", { next: { revalidate: 0 } }),
  healthRaw: () =>
    fetch(`${API_BASE}/health`, { cache: "no-store" }).then((r) => r.ok),

  admit: (body: {
    path: string;
    source?: string;
    expected_digest?: string;
    sandbox_mode?: string;
    malicious?: boolean;
  }) =>
    request<AdmissionResponse>("/artifacts/admit", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  admitNpm: (body: {
    spec: string;
    npm_mode: "offline" | "live" | "auto";
    source?: string;
    sandbox_mode?: string;
  }) =>
    request<AdmissionResponse>("/artifacts/admit/npm", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  verify: (path: string, expected_digest: string) =>
    request<{
      path: string;
      expected_digest: string;
      computed_digest: string;
      integrity: string;
      passed: boolean;
      detail: string;
    }>("/artifacts/verify", {
      method: "POST",
      body: JSON.stringify({ path, expected_digest }),
    }),

  artifacts: () => request<ArtifactRecord[]>("/artifacts"),
  events: () => request<EventRecord[]>("/events"),
  passport: (id: string) => request<PassportRecord>(`/artifacts/${id}/passport`),

  promote: (id: string) =>
    request<{ status: string; state: string }>(`/artifacts/${id}/promote`, {
      method: "POST",
    }),

  rollback: (packageName: string) =>
    request<{ package: string; version: string; available: boolean }>(
      `/artifacts/rollback/${encodeURIComponent(packageName)}`,
      { method: "POST" }
    ),
};