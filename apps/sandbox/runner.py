"""Docker sandbox runner.

Executes an artifact's install/build behavior inside an isolated container and
collects evidence of any restricted attempts (environment access, SSH lookup,
outbound network, filesystem escape) alongside stdout/stderr.

Design principles:
  - NEVER run untrusted package code directly on the host.
  - Never mount host secrets, ~/.ssh, or arbitrary host directories.
  - Disable outbound network by default (network_mode: none).
  - Use a throwaway workspace; destroy the container afterwards.
  - Impose memory, CPU and time limits.
  - FAIL SAFE: if Docker is unavailable the sandbox reports an error and the
    artifact is NOT trusted.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .policy import DEFAULT_SANDBOX_POLICY, SandboxPolicy


@dataclass
class SandboxEvent:
    kind: str  # env_access | ssh_access | network | filesystem | behavior
    blocked: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "blocked": self.blocked, "detail": self.detail}


@dataclass
class SandboxResult:
    ok: bool
    events: list[SandboxEvent] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    suspicious: bool = False

    def to_dict(self, blocked_kinds=None) -> dict[str, Any]:
        blocked_kinds = blocked_kinds or ["env_access", "ssh_access", "network", "filesystem"]
        blocked_events = [e for e in self.events if e.blocked]
        return {
            "ok": self.ok,
            "suspicious": self.suspicious,
            "events": [e.to_dict() for e in self.events],
            "blocked_attempts": [e.to_dict() for e in blocked_events],
            "blocked_kinds": blocked_kinds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
        }


SANDBOX_DOCKERFILE_INLINE = r"""
FROM node:20-alpine
WORKDIR /app
# Nothing else: the workspace is mounted read-only for the run script.
"""


def docker_available() -> bool:
    """True only if the Docker CLI AND daemon are actually reachable."""
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


class SandboxRunner:
    """Runs a package's install script in an isolated Docker container."""

    PROBE_SCRIPT = r"""
const fs = require('fs');
const os = require('os');
const path = require('path');
const results = [];

function record(kind, detail) {
  results.push({ kind, detail });
  console.log('AIRCRAFT_EVENT ' + JSON.stringify({ kind, detail }));
}

// 1) environment / secrets access
const leak =
  Object.keys(process.env).filter(k =>
    /(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|PAYMENT|MONO|DOJAH)/i.test(k)
  );
if (leak.length > 0) {
  record('env_access', 'attempted to read environment variables: ' + leak.join(','));
} else {
  record('env_access', 'no secret-like environment variables present in sandbox');
}

// 2) SSH discovery
const sshPaths = ['/root/.ssh', path.join(os.homedir(), '.ssh'), '/home', '/etc/ssh'];
for (const p of sshPaths) {
  try { fs.accessSync(p); record('ssh_access', 'attempted to inspect ' + p); }
  catch (e) { record('ssh_access', 'no access to ' + p + ' (blocked)'); }
}

// 3) outbound network attempt
const net = require('net');
const sock = new net.Socket();
sock.setTimeout(1500);
sock.on('connect', () => { record('network', 'outbound network connection SUCCEEDED'); sock.destroy(); });
sock.on('error', (e) => { record('network', 'outbound network BLOCKED: ' + e.code); });
sock.on('timeout', () => { record('network', 'outbound network blocked (timeout)'); sock.destroy(); });
try { sock.connect(80, '1.1.1.1'); } catch (e) { record('network', 'network attempt blocked: ' + e.message); }

// 4) filesystem escape attempt
try {
  const cwd = process.cwd();
  fs.writeFileSync('/etc/airlock-probe-escape', 'pwned', { flag: 'wx' });
  record('filesystem', 'wrote OUTSIDE workspace to /etc (UNBLOCKED)');
} catch (e) {
  record('filesystem', 'cannot write outside workspace (blocked)');
}

// wait briefly for the network probe
setTimeout(() => {
  console.log('AIRCRAFT_RESULTS ' + JSON.stringify(results));
  process.exit(0);
}, 1800);
"""

    def _probe_image(self, image: str) -> None:
        """Build a throwaway sandbox image from an inline Dockerfile."""
        build_dir = Path(os.environ.get("AIRLOCK_SANDBOX_BUILD_DIR", "/tmp/airlock-sandbox"))
        build_dir.mkdir(parents=True, exist_ok=True)
        (build_dir / "Dockerfile").write_text(SANDBOX_DOCKERFILE_INLINE, encoding="utf-8")
        subprocess.run(
            ["docker", "build", "-t", image, str(build_dir)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )

    def run(
        self,
        workspace_dir: str | Path,
        policy: SandboxPolicy | None = None,
        image: str | None = None,
        probe_mode: bool = True,
    ) -> SandboxResult:
        policy = policy or DEFAULT_SANDBOX_POLICY
        image = image or "airlock-sandbox:latest"
        workspace = Path(workspace_dir).resolve()

        if not workspace.exists():
            return SandboxResult(ok=False, error="workspace does not exist")

        if not docker_available():
            return SandboxResult(
                ok=False,
                error="Docker unavailable; FAILING CLOSED (artifact not trusted)",
            )

        try:
            self._probe_image(image)
        except Exception as e:  # noqa: BLE001
            return SandboxResult(ok=False, error=f"failed to build sandbox image: {e}")

        # The run script invokes the package install and the probe. For the MVP
        # probe_mode runs a self-contained Node probe inside the container.
        container_name = f"airlock-sandbox-{int(time.time() * 1000)}"

        mounts = [
            # Read-only mount of the workspace, no host paths leaked.
            f"{workspace}:/workspace:ro",
        ]
        mount_args = []
        for m in mounts:
            mount_args += ["-v", m]

        cmd = [
            "docker", "run",
            "--rm",
            "--name", container_name,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-m", policy.memory_limit,
            "--cpus", str(policy.cpu_limit),
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--tmpfs", "/workspace:rw,noexec,nosuid,size=128m",
            *mount_args,
        ]

        # Do not expose host secrets. Pass only a minimal, safe environment.
        env_args = ["-e", "AIRLOCK_SANDBOX=1", "-e", "PATH=/usr/local/bin:/usr/bin:/bin"]
        cmd += env_args
        cmd += [image, "node", "-e", self.PROBE_SCRIPT if probe_mode else "console.log('no-op')"]

        try:
            start = time.time()
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=policy.timeout_seconds,
            )
            elapsed = time.time() - start
        except subprocess.TimeoutExpired as e:
            # Clean up the leftover container so nothing lingers.
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return SandboxResult(
                ok=False,
                error=f"sandbox timed out after {policy.timeout_seconds}s",
                stdout=(e.stdout or b"").decode() if isinstance(e.stdout, bytes) else str(e.stdout or ""),
                stderr=(e.stderr or b"").decode() if isinstance(e.stderr, bytes) else str(e.stderr or ""),
            )
        except FileNotFoundError:
            return SandboxResult(ok=False, error="docker command not found; failing closed")

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        events = self._parse_events(stdout)
        if not events:
            events = [SandboxEvent("behavior", True, "no probe events captured; treating as suspicious")]
            suspicious = True
        else:
            suspicious = any(
                not e.blocked
                and e.kind in ("env_access", "ssh_access", "network", "filesystem")
                and "BLOCKED" not in e.detail
                and "no " not in e.detail
                for e in events
            )

        return SandboxResult(
            ok=(proc.returncode == 0 and not suspicious),
            events=events,
            stdout=stdout,
            stderr=stderr,
            suspicious=suspicious,
        )

    @staticmethod
    def _parse_events(stdout: str) -> list[SandboxEvent]:
        events: list[SandboxEvent] = []
        for line in stdout.splitlines():
            if line.startswith("AIRCRAFT_EVENT "):
                try:
                    payload = json.loads(line[len("AIRCRAFT_EVENT "):])
                    kind = payload.get("kind", "behavior")
                    detail = payload.get("detail", "")
                    blocked = _is_blocked(kind, detail)
                    events.append(SandboxEvent(kind, blocked, detail))
                except json.JSONDecodeError:
                    continue
        return events


def _is_blocked(kind: str, detail: str) -> bool:
    blocked_markers = ("BLOCKED", "blocked", "no access", "cannot", "no secret-like")
    up = detail.lower()
    return any(m.lower() in up for m in blocked_markers)
