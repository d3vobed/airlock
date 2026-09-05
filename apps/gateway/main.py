"""AIRLOCK Gateway — FastAPI application entrypoint."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .deps import app_state
from .routes import artifacts, health, promote, verify

settings.ensure_dirs()

app = FastAPI(
    title="AIRLOCK Gateway",
    description=(
        "Admission-control layer between external third-party software and an "
        "organization's trusted software supply chain. ADMIT or REJECT — never "
        "trust an external artifact just because it has a familiar name."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(artifacts.router)
app.include_router(verify.router)
app.include_router(promote.router)


@app.on_event("startup")
def _startup() -> None:
    settings.ensure_dirs()


@app.get("/")
def root():
    return {
        "service": "airlock-gateway",
        "docs": "/docs",
        "health": "/health",
    }