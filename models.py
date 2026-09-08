"""
ScamShield AI — Pydantic Schemas
Defines the request/response contracts for every REST endpoint.
Keeping these separate from main.py keeps the API surface easy to version
and lets the frontend and backend evolve independently.
"""

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

class Verdict:
    """Allowed verdict labels, kept as constants instead of a bare str
    so the frontend and backend can't silently drift on spelling."""
    SAFE = "safe"
    CAUTION = "caution"
    DANGER = "danger"


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "scamshield-ai-backend"
    version: str = "1.0.0"
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# QR / Link analysis
# ---------------------------------------------------------------------------

class QRAnalysisRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Raw text decoded from the QR code (usually a URL).",
    )
    region: Optional[str] = Field(
        default=None,
        description="Optional ISO region hint (e.g. 'US', 'GB') for locale-aware checks.",
    )


class QRFinding(BaseModel):
    code: str
    label: str
    weight: int


class QRAnalysisResponse(BaseModel):
    content: str
    risk_score: int = Field(..., ge=0, le=100)
    verdict: str
    findings: List[QRFinding]
    resolved_host: Optional[str] = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Voice / call transcript analysis
# ---------------------------------------------------------------------------

class VoiceAnalysisRequest(BaseModel):
    transcript: str = Field(
        ...,
        min_length=1,
        max_length=8000,
        description="Transcribed text of a live or recorded call snippet.",
    )
    region: Optional[str] = Field(
        default=None,
        description="Optional ISO region hint, used to weight region-specific scam scripts.",
    )


class VoiceCategoryHit(BaseModel):
    category: str
    label: str
    matched_phrases: List[str]
    weight: int


class VoiceAnalysisResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    verdict: str
    categories: List[VoiceCategoryHit]
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
