"""Verification endpoints — re-verify an artifact against an expected digest."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from core.hashing.sha256 import sha256_file
from apps.gateway.services.verifier import Verifier
from ..schemas import VerifyRequest

router = APIRouter(prefix="/artifacts", tags=["verify"])


@router.post("/verify")
def verify(req: VerifyRequest):
    """Verify an artifact file against an expected SHA-256 digest."""
    try:
        result = Verifier().verify_file_against(req.path, req.expected_digest)
        return {
            "path": req.path,
            "expected_digest": req.expected_digest,
            "computed_digest": sha256_file(req.path),
            "integrity": result.integrity.value,
            "passed": result.passed,
            "detail": result.detail,
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="artifact not found")