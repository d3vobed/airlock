"""Shared application state for the gateway (singleton services)."""
from __future__ import annotations

from .services.admission import AdmissionPipeline
from .services.fallback import FallbackService
from .services.passport import PassportService
from .store import Storage


class AppState:
    def __init__(self):
        self.storage = Storage()
        self.passport_svc = PassportService(self.storage)
        self.fallback_svc = FallbackService(self.storage)

    def pipeline(self, sandbox_mode: str | None = None, malicious: bool = False) -> AdmissionPipeline:
        return AdmissionPipeline(storage=self.storage, sandbox_mode=sandbox_mode, malicious=malicious)


app_state = AppState()