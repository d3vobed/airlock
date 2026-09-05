"""Health and metadata endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from ..deps import app_state

router = APIRouter(tags=["health"])


@router.get("/health")
def health():
    """Liveness + readiness check."""
    try:
        app_state.storage.connect().execute("SELECT 1")
        db = "ok"
    except Exception:  # noqa: BLE001
        db = "error"
    return {"status": "ok", "service": "airlock-gateway", "db": db}


@router.get("/events")
def events():
    """Recent security-relevant admission events (audit trail)."""
    return app_state.storage.list_events()