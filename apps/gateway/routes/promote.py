"""Promote and rollback endpoints for the trusted registry and LKG."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..deps import app_state

router = APIRouter(prefix="/artifacts", tags=["promote"])


@router.post("/{artifact_id}/promote")
def promote(artifact_id: str):
    """Promote an artifact as the trusted internal artifact.

    Promotion only sets a flag on the stored record; a rejected artifact can
    never be promoted unless re-admitted through the full pipeline.
    """
    record = app_state.storage.get_artifact(artifact_id)
    if not record:
        raise HTTPException(status_code=404, detail="artifact not found")
    if record.get("state") == "REJECTED":
        raise HTTPException(status_code=409, detail="rejected artifact cannot be promoted")
    if record.get("state") not in ("INTERNAL", "BUILDABLE", "VERIFIED"):
        raise HTTPException(status_code=409, detail="artifact is not in a promotable state")
    record["state"] = "BUILDABLE"
    app_state.storage.save_artifact(record)
    return {"artifact_id": artifact_id, "status": "promoted", "state": "BUILDABLE"}


@router.post("/{artifact_id}/rollback")
def rollback(artifact_id: str):
    """Expose LKG fallback for the package the artifact belongs to."""
    record = app_state.storage.get_artifact(artifact_id)
    if not record:
        raise HTTPException(status_code=404, detail="artifact not found")
    result = app_state.fallback_svc.get_lkg(record["package"])
    if not result:
        raise HTTPException(status_code=404, detail="no last known good artifact available")
    return result


@router.post("/rollback/{package}")
def rollback_by_package(package: str):
    """Expose LKG fallback for a package by name."""
    result = app_state.fallback_svc.rollback(package)
    if not result:
        raise HTTPException(status_code=404, detail="no last known good artifact available")
    return result