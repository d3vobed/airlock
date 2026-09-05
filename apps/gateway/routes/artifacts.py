"""Artifact admission and listing endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..deps import app_state
from ..schemas import AdmitNpmRequest, AdmitRequest

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


class AdmitResponse(BaseModel):
    artifact_id: str
    package: str
    version: str
    digest: str
    source: str
    state: str
    decision: str
    reason: str | None
    checks: list[dict]
    sandbox: dict
    lkg: dict | None
    passport: dict
    timestamp: str
    registry: str | None = None
    tarball_url: str | None = None


@router.post("/admit", response_model=AdmitResponse)
def admit(req: AdmitRequest) -> AdmitResponse:
    """Admit an artifact tarball into the AIRLOCK admission pipeline."""
    try:
        result = app_state.pipeline(
            sandbox_mode=req.sandbox_mode, malicious=req.malicious
        ).admit(
            req.path,
            source=req.source,
            expected_digest=req.expected_digest,
        )
        return AdmitResponse(**result)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/admit/npm", response_model=AdmitResponse)
def admit_npm(req: AdmitNpmRequest) -> AdmitResponse:
    """Admit a real npm package (name@version) through the full pipeline."""
    try:
        result = app_state.pipeline(sandbox_mode=req.sandbox_mode).admit_npm(
            req.spec, npm_mode=req.npm_mode, source=req.source
        )
        return AdmitResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("")
def list_artifacts():
    """List all artifacts that have gone through admission."""
    return app_state.storage.list_artifacts()


@router.get("/{artifact_id}")
def get_artifact(artifact_id: str):
    """Fetch a single artifact record by artifact ID."""
    record = app_state.storage.get_artifact(artifact_id)
    if not record:
        raise HTTPException(status_code=404, detail="artifact not found")
    return record


@router.get("/{artifact_id}/passport")
def get_passport(artifact_id: str):
    """Fetch the Supply Chain Passport for an artifact."""
    p = app_state.passport_svc.get(artifact_id)
    if not p:
        raise HTTPException(status_code=404, detail="passport not found")
    return p.model_dump()