"use client";

import { useCallback, useEffect, useState } from "react";
import {
  api,
  AdmissionResponse,
  ArtifactRecord,
  EventRecord,
  Health,
  PassportRecord,
} from "@/lib/api";
import { DEMO_CASES, DemoCase } from "@/demo/cases";

/* ---------------------------------------------------------------- status */
const DECISION_STYLES: Record<string, string> = {
  TRUSTED: "bg-emerald-500/15 text-emerald-300 ring-emerald-400/30",
  REJECTED: "bg-rose-500/15 text-rose-300 ring-rose-400/30",
  PROMOTED: "bg-sky-500/15 text-sky-300 ring-sky-400/30",
};

const CHECK_STYLES: Record<string, string> = {
  passed: "bg-emerald-500/10 text-emerald-300",
  failed: "bg-rose-500/10 text-rose-300",
  unavailable: "bg-amber-500/10 text-amber-300",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">
        {title}
      </h2>
      {children}
    </section>
  );
}

function Badge({ label }: { label: string }) {
  const style = DECISION_STYLES[label] || "bg-slate-500/15 text-slate-300 ring-slate-400/30";
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-bold ring-1 ${style}`}
    >
      {label}
    </span>
  );
}

function Pip({ n, s }: { n: string; s: string }) {
  const style = CHECK_STYLES[s] || CHECK_STYLES.unavailable;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="h-2 w-2 rounded-full" style={chkColor(s)} />
      <span className="font-medium text-slate-300">{n}</span>
    </div>
  );
}
function chkColor(s: string) {
  if (s === "passed") return { background: "#10b981" };
  if (s === "failed") return { background: "#f43f5e" };
  return { background: "#f59e0b" };
}

const fmt = (s?: string) => (s ? s.slice(0, 12) + "…" + s.slice(-8) : "");

/* ------------------------------------------------------------- result card */
function DecisionCard({ r }: { r: AdmissionResponse }) {
  return (
    <div className="space-y-4 rounded-lg border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-mono text-lg font-bold">{fmt(r.artifact_id)}</div>
          <div className="text-sm text-slate-400">
            {r.package}@{r.version}
          </div>
        </div>
        <Badge label={r.decision} />
      </div>

      <div className="flex flex-wrap gap-4 text-xs text-slate-400">
        <span>
          digest: <span className="font-mono text-slate-300">{fmt(r.digest)}</span>
        </span>
        <span>source: {r.source}</span>
        <span>state: {r.state}</span>
        {r.registry && <span>registry: {r.registry}</span>}
        {r.tarball_url && (
          <a
            className="underline decoration-dotted"
            href={r.tarball_url}
            target="_blank"
            rel="noreferrer"
          >
            tarball
          </a>
        )}
      </div>

      {r.reason && (
        <div className="rounded bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
          <strong>Reason:</strong> {r.reason}
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4">
        {r.checks.map((c) => (
          <div
            key={c.name}
            className="rounded border border-slate-800 bg-slate-950/60 p-2"
          >
            <Pip n={c.name} s={c.status} />
            <div className="mt-1 line-clamp-2 text-[11px] text-slate-500">{c.detail}</div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-3 border-t border-slate-800 pt-3 text-xs text-slate-400">
        <span>
          Sandbox: <span className="font-mono text-slate-300">{r.sandbox.mode}</span>{" "}
          <span className={r.sandbox.ok ? "text-emerald-300" : "text-rose-300"}>
            {r.sandbox.ok ? "clean" : "failed/blocked"}
          </span>
        </span>
        <span>
          Provenance:{" "}
          <span className="font-mono text-slate-300">
            {String(r.passport.provenance ?? "unavailable")}
          </span>
        </span>
        {r.lkg && (
          <span>
            LKG available: <span className="font-mono text-slate-300">{r.lkg.version}</span>
          </span>
        )}
        <span className="ml-auto font-mono text-slate-500">{r.timestamp}</span>
      </div>
    </div>
  );
}

function PassportCard({ p }: { p: PassportRecord }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-sm">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Supply Chain Passport
        </div>
        <Badge label={p.status} />
      </div>
      <div className="grid gap-1 font-mono text-xs text-slate-300">
        <div>artifact : {fmt(p.artifact_id)}</div>
        <div>digest   : {fmt(p.digest)}</div>
        <div>source   : {p.source}</div>
        <div>sandbox  : {p.sandbox?.mode} / {p.sandbox?.ok ? "clean" : "blocked"}</div>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- controls */
function useAdmit() {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AdmissionResponse | null>(null);
  const [passport, setPassport] = useState<PassportRecord | null>(null);

  const run = useCallback(async (case_: DemoCase) => {
    setRunning(true);
    setError(null);
    setResult(null);
    setPassport(null);
    try {
      const r =
        case_.kind === "npm" && case_.npm
          ? await api.admitNpm({
              spec: case_.npm.spec,
              npm_mode: case_.npm.mode,
              sandbox_mode: "simulate",
            })
          : await api.admit({
              path: case_.path!,
              source: case_.source,
              expected_digest: case_.digest,
              sandbox_mode: "simulate",
              malicious: !!case_.malicious,
            });
      setResult(r);
      try {
        const p = await api.passport(r.artifact_id);
        setPassport(p);
      } catch {
        setPassport(null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }, []);

  return { running, error, result, passport, run };
}

/* --------------------------------------------------------------- list bits */
function EventRow({ e }: { e: EventRecord }) {
  return (
    <div className="flex items-center gap-3 border-b border-slate-800/60 py-1.5 text-xs">
      <Badge label={e.decision} />
      <span className="font-mono text-slate-200">
        {e.package}@{e.version}
      </span>
      <span className="ml-auto font-mono text-slate-500">{fmt(e.artifact_id)}</span>
    </div>
  );
}

function ArtifactRow({
  a,
  onRollback,
}: {
  a: ArtifactRecord;
  onRollback: (pkg: string) => void;
}) {
  return (
    <div className="flex items-center gap-3 border-b border-slate-800/60 py-1.5 text-xs">
      <Badge label={a.state} />
      <span className="w-40 truncate font-mono text-slate-200">
        {a.package}@{a.version}
      </span>
      <span className="hidden text-slate-500 sm:inline">{a.source}</span>
      <span className="ml-auto hidden font-mono text-slate-500 md:inline">
        {fmt(a.digest)}
      </span>
      {a.state === "REJECTED" && (
        <button
          onClick={() => onRollback(a.package)}
          className="rounded bg-sky-500/15 px-2 py-0.5 text-sky-200 ring-1 ring-sky-400/30 hover:bg-sky-500/25"
        >
          rollback
        </button>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------- page */
export default function Home() {
  const { running, error, result, passport, run } = useAdmit();
  const [health, setHealth] = useState<Health | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [artifacts, setArtifacts] = useState<ArtifactRecord[]>([]);
  const [rollbackMsg, setRollbackMsg] = useState<string | null>(null);
  const [active, setActive] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setHealth(await api.health());
    } catch {
      setHealth({ status: "down", service: "airlock-gateway", db: "unknown" });
    }
    try {
      setEvents(await api.events());
    } catch {
      setEvents([]);
    }
    try {
      setArtifacts(await api.artifacts());
    } catch {
      setArtifacts([]);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  const onRun = useCallback(
    async (c: DemoCase) => {
      setActive(c.id);
      setRollbackMsg(null);
      await run(c);
    },
    [run]
  );

  const onRollback = useCallback(async (pkg: string) => {
    try {
      const r = await api.rollback(pkg);
      setRollbackMsg(`${r.package} rolled back to LKG ${r.version}`);
    } catch (e) {
      setRollbackMsg(e instanceof Error ? e.message : String(e));
    }
    refresh();
  }, [refresh]);

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      {/* header */}
      <header className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">
              AIRLOCK{" "}
              <span className="bg-gradient-to-r from-sky-400 to-emerald-400 bg-clip-text text-transparent">
                Supply Chain Admission
              </span>
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Gate third-party software before it enters the trusted build chain.
            </p>
          </div>
          <div
            className={`flex items-center gap-2 rounded border px-3 py-1.5 text-xs ${
              health?.status === "ok"
                ? "border-emerald-500/30 text-emerald-300"
                : "border-rose-500/30 text-rose-300"
            }`}
          >
            <span className="h-2 w-2 rounded-full bg-current" />
            {health?.status === "ok" ? "gateway online" : "gateway offline"}
            <span className="text-slate-500">db: {health?.db ?? "…"}</span>
          </div>
        </div>
      </header>

      {/* demo selector */}
      <Section title="Run a demo scenario">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {DEMO_CASES.map((c) => (
            <button
              key={c.id}
              onClick={() => onRun(c)}
              disabled={running}
              className={`rounded border p-3 text-left text-sm transition ${
                active === c.id
                  ? "border-sky-500/50 bg-sky-500/10"
                  : "border-slate-800 bg-slate-900/40 hover:border-slate-600"
              }`}
            >
              <div className="font-semibold text-slate-100">{c.label}</div>
              <div className="mt-1 line-clamp-3 text-xs text-slate-400">
                {c.description}
              </div>
            </button>
          ))}
        </div>

        {running && (
          <div className="mt-4 flex items-center gap-2 text-sm text-sky-300">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
            running admission pipeline…
          </div>
        )}
        {error && (
          <div className="mt-4 rounded bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
            <strong>Error:</strong> {error}
          </div>
        )}
      </Section>

      {/* result */}
      {(result || passport) && (
        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <Section title="Decision">
              {result && <DecisionCard r={result} />}
            </Section>
          </div>
          <div>
            <Section title="Artifact detail">{passport && <PassportCard p={passport} />}</Section>
          </div>
        </div>
      )}

      {rollbackMsg && (
        <div className="mt-4 rounded border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-sm text-sky-200">
          {rollbackMsg}
        </div>
      )}

      {/* live view */}
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Section title="Recent admission decisions (audit trail)">
          {events.length === 0 ? (
            <p className="text-sm text-slate-500">No decisions yet.</p>
          ) : (
            events.map((e, i) => <EventRow key={i} e={e} />)
          )}
        </Section>
        <Section title="Artifact ledger">
          {artifacts.length === 0 ? (
            <p className="text-sm text-slate-500">No artifacts yet.</p>
          ) : (
            artifacts.map((a) => (
              <ArtifactRow key={a.artifact_id} a={a} onRollback={onRollback} />
            ))
          )}
        </Section>
      </div>
    </main>
  );
}