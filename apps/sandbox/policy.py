"""Sandbox policy — defines what a sandboxed artifact is permitted to do.

The sandbox enforces these restrictions on untrusted package execution:
  - no host secrets / environment access
  - no ~/.ssh discovery
  - restricted, throwaway filesystem
  - no outbound network by default
  - resource and time limits
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SandboxPolicy:
    network_enabled: bool = False
    secrets_allowed: bool = False
    ssh_allowed: bool = False
    filesystem_restricted: bool = True
    memory_limit: str = "256m"
    cpu_limit: float = 0.5
    timeout_seconds: int = 30
    # Deny-list of environment variables we never want to expose to the sandbox.
    forbidden_env: tuple[str, ...] = (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NPM_TOKEN",
        "SLACK_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DATABASE_URL",
        "PAYMENT_SECRET",
        "MONO_SECRET",
        "DOJAH_SECRET",
        "HOME_SSH",
    )


DEFAULT_SANDBOX_POLICY = SandboxPolicy()
