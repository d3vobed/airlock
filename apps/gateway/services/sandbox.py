"""Sandbox orchestration service.

Chooses the isolation mode for executing an artifact's install/build behavior:
  - docker     : real container isolation (network none, secrets denied,
                 restricted filesystem). FAILS CLOSED on any docker error.
  - simulate   : safe, deterministic simulation for demos / CI / fresh laptops
                 where Docker is unavailable. Does NOT execute untrusted code on
                 the host. The passport MUST reflect that simulation was used.

When Docker is available it is always preferred. If sandbox mode is 'docker'
and Docker is unavailable, the artifact FAILS CLOSED (it is not trusted).

Two execution forms:
  - probe         : runs AIRLOCK's self-contained behavior probe against the
                    unpacked artifact workspace (used by the fully synthetic demos).
  - npm_install   : performs a REAL ``npm install <tarball>`` inside the isolated
                    container so the artifact's actual lifecycle scripts run.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from core.models.artifact import Artifact
from core.models.passport import CheckStatus

from ..config import settings
from ...sandbox.policy import SandboxPolicy
from ...sandbox.runner import SandboxEvent, SandboxResult, SandboxRunner, docker_available

SIMULATED_BLOCKS = [
    {"kind": "env_access", "blocked": True, "detail": "environment/secret access attempt BLOCKED (simulated)"},
    {"kind": "ssh_access", "blocked": True, "detail": "~/.ssh discovery BLOCKED (simulated)"},
    {"kind": "network", "blocked": True, "detail": "outbound network attempt BLOCKED (simulated)"},
    {"kind": "filesystem", "blocked": True, "detail": "write outside workspace BLOCKED (simulated)"},
]


class SandboxService:
    """Executes artifact behavior in quarantine and reports suspicious activity."""

    def __init__(self, mode: str | None = None, malicious: bool = False):
        # malicious=True drives the simulate-mode result toward rejection, used
        # for the malicious-package demo. In docker mode the real runtime decides.
        self.mode = (mode or os.environ.get("AIRLOCK_SANDBOX_MODE", "auto")).lower()
        self.malicious = malicious
        self.runner = SandboxRunner()

    def _effective_mode(self) -> str:
        if self.mode == "auto":
            return "docker" if docker_available() else "simulate"
        return self.mode

    def execute(
        self,
        workspace: str | Path,
        artifact: Artifact | None = None,
        npm_install: bool = False,
    ) -> tuple[SandboxResult, str, CheckStatus]:
        """Run the artifact's behavior. Returns (result, mode, status)."""
        mode = self._effective_mode()

        if mode == "docker":
            if npm_install and artifact:
                result = self.runner.run_npm_install(artifact.manifest_path)
            else:
                result = self.runner.run(workspace)
            if result.error:
                return result, "docker", CheckStatus.FAILED
            status = CheckStatus.PASSED if result.ok else CheckStatus.FAILED
            return result, "docker", status

        if mode == "simulate":
            result = self._simulate(artifact, npm_install=npm_install)
            status = CheckStatus.PASSED if result.ok else CheckStatus.FAILED
            return result, "simulate", status

        # Unknown mode: fail closed.
        return SandboxResult(ok=False, error=f"unknown sandbox mode '{mode}'"), mode, CheckStatus.FAILED

    def _simulate(self, artifact: Artifact | None, npm_install: bool = False) -> SandboxResult:
        if self.malicious:
            # Malicious demo package: report blocked attempts, but also flag the
            # package supplied a malicious install script -> suspicious/reject.
            events_dict = list(SIMULATED_BLOCKS) + [
                {"kind": "behavior", "blocked": True, "detail": "malicious install script detected (demo)"}
            ]
            suspicious = True
            ok = False
        else:
            events_dict = list(SIMULATED_BLOCKS)
            if npm_install and artifact:
                scripts = getattr(artifact, "policy", {}).get("lifecycle_scripts", [])
                if scripts:
                    events_dict.append(
                        {"kind": "lifecycle", "blocked": True,
                         "detail": f"npm lifecycle executed (simulated): {', '.join(scripts)}"}
                    )
            suspicious = False
            ok = True

        events = [SandboxEvent(e["kind"], e["blocked"], e["detail"]) for e in events_dict]
        return SandboxResult(ok=ok, events=events, suspicious=suspicious, error=None)


def prepare_workspace(artifact: Artifact, marker: str = "") -> Path:
    """Create a throwaway workspace containing the artifact unpacked for probing."""
    from ..artifact_io import flatten_tarball

    ws = Path(settings.quarantine_dir) / f"_ws_{artifact.package.replace('/', '__')}_{marker}"
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True, exist_ok=True)
    flatten_tarball(artifact.manifest_path, ws)
    return ws