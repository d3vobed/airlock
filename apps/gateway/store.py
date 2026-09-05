"""SQLite persistence for admission records, passports and decisions."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import REPO_ROOT, Settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Storage:
    """Minimal SQLite-backed store.

    Keeps the schema intentionally small: one table for artifacts, one for
    passports, and one for decisions. This is a hackathon-grade store, not a
    distributed database.
    """

    def __init__(self, path: str | None = None):
        self.path = path or str(REPO_ROOT / "airlock.db")
        self._init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    package TEXT,
                    version TEXT,
                    source TEXT,
                    publisher TEXT,
                    digest TEXT,
                    state TEXT,
                    reason TEXT,
                    manifest_path TEXT,
                    created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS passports (
                    artifact_id TEXT PRIMARY KEY,
                    payload TEXT,
                    created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_id TEXT,
                    package TEXT,
                    version TEXT,
                    decision TEXT,
                    reason TEXT,
                    created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS lkg (
                    package TEXT PRIMARY KEY,
                    version TEXT,
                    artifact_id TEXT,
                    digest TEXT,
                    created_at TEXT
                );
                """
            )

    def _ensure_cols(self, conn) -> None:
        pass

    def save_artifact(self, a: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO artifacts
                (artifact_id, package, version, source, publisher, digest, state, reason, manifest_path, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    a.get("artifact_id", ""),
                    a.get("package"),
                    a.get("version"),
                    a.get("source"),
                    a.get("publisher"),
                    a.get("digest"),
                    a.get("state"),
                    a.get("reason"),
                    a.get("manifest_path"),
                    _now(),
                ),
            )

    def get_artifact(self, artifact_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_artifacts(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM artifacts ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def save_passport(self, artifact_id: str, payload: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO passports (artifact_id, payload, created_at) VALUES (?,?,?)",
                (artifact_id, json.dumps(payload), _now()),
            )

    def get_passport(self, artifact_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM passports WHERE artifact_id=?", (artifact_id,)
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def add_decision(self, d: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO decisions (artifact_id, package, version, decision, reason, created_at) VALUES (?,?,?,?,?,?)",
                (
                    d.get("artifact_id"),
                    d.get("package"),
                    d.get("version"),
                    d.get("decision"),
                    d.get("reason"),
                    _now(),
                ),
            )

    def save_lkg(self, package: str, version: str, artifact_id: str, digest: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO lkg (package, version, artifact_id, digest, created_at) VALUES (?,?,?,?,?)",
                (package, version, artifact_id, digest, _now()),
            )

    def get_lkg(self, package: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM lkg WHERE package=?", (package,)
            ).fetchone()
        return dict(row) if row else None

    def list_events(self) -> list[dict]:
        """Security-relevant admission events for audit (not a monitoring tool)."""
        events = []
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT artifact_id, package, version, decision, reason, created_at FROM decisions ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
            events = [dict(r) for r in rows]
        return events
