"""Gateway configuration and runtime state."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: _env("AIRLOCK_DB_PATH", "airlock.db"))
    trusted_dir: str = field(default_factory=lambda: _env("AIRLOCK_TRUSTED_DIR", str(REPO_ROOT / "registry" / "trusted")))
    quarantine_dir: str = field(default_factory=lambda: _env("AIRLOCK_QUARANTINE_DIR", str(REPO_ROOT / "registry" / "quarantine")))
    rejected_dir: str = field(default_factory=lambda: _env("AIRLOCK_REJECTED_DIR", str(REPO_ROOT / "registry" / "rejected")))
    lkg_dir: str = field(default_factory=lambda: _env("AIRLOCK_LKG_DIR", str(REPO_ROOT / "registry" / "lkg")))
    policy_file: str = field(default_factory=lambda: _env("AIRLOCK_POLICY_FILE", str(REPO_ROOT / "core" / "policies" / "default.yaml")))
    sandbox_enabled: str = field(default_factory=lambda: _env("AIRLOCK_SANDBOX_ENABLED", "true"))
    sandbox_image: str = field(default_factory=lambda: _env("AIRLOCK_SANDBOX_IMAGE", "airlock-sandbox:latest"))
    sandbox_timeout: int = field(default_factory=lambda: int(_env("AIRLOCK_SANDBOX_TIMEOUT_SECONDS", "30")))
    cors_origins: list = field(default_factory=lambda: _env("AIRLOCK_CORS_ORIGINS", "http://localhost:3000").split(","))

    def sandbox_on(self) -> bool:
        return self.sandbox_enabled.lower() in ("1", "true", "yes")

    def ensure_dirs(self) -> None:
        for d in (self.trusted_dir, self.quarantine_dir, self.rejected_dir, self.lkg_dir):
            Path(d).mkdir(parents=True, exist_ok=True)


settings = Settings()
