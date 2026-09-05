"""Admission decision models."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Decision(str, Enum):
    TRUSTED = "TRUSTED"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"


class DecisionRecord(BaseModel):
    artifact_id: str
    package: str
    version: str
    decision: Decision
    reason: str | None = None
    state: str = ""
    details: dict = {}
