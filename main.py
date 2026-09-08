"""
ScamShield AI — FastAPI Backend

Run locally:
    uvicorn app.main:app --reload --port 8000

Endpoints:
    GET  /api/health           liveness check
    POST /api/analyze/qr       score a decoded QR/link payload
    POST /api/analyze/voice    score a call transcript snippet
"""

import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import (
    HealthResponse,
    QRAnalysisRequest,
    QRAnalysisResponse,
    VoiceAnalysisRequest,
    VoiceAnalysisResponse,
)
from app.services import qr_service, voice_service

load_dotenv()

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]

app = FastAPI(
    title="ScamShield AI API",
    description="Heuristic scam-detection endpoints for QR codes and call transcripts.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse()


@app.post("/api/analyze/qr", response_model=QRAnalysisResponse, tags=["analysis"])
def analyze_qr(payload: QRAnalysisRequest) -> QRAnalysisResponse:
    if not payload.content.strip():
        raise HTTPException(status_code=422, detail="content must not be empty")

    findings = qr_service.analyze_qr_content(payload.content, payload.region)
    score = qr_service.score_findings(findings)
    verdict = qr_service.verdict_from_score(score)

    resolved_host = None
    try:
        from urllib.parse import urlparse
        text = payload.content.strip()
        normalized = text if "://" in text else f"http://{text}"
        resolved_host = urlparse(normalized).hostname
    except Exception:
        resolved_host = None

    return QRAnalysisResponse(
        content=payload.content,
        risk_score=score,
        verdict=verdict,
        findings=findings,
        resolved_host=resolved_host,
    )


@app.post("/api/analyze/voice", response_model=VoiceAnalysisResponse, tags=["analysis"])
def analyze_voice(payload: VoiceAnalysisRequest) -> VoiceAnalysisResponse:
    if not payload.transcript.strip():
        raise HTTPException(status_code=422, detail="transcript must not be empty")

    categories = voice_service.analyze_transcript(payload.transcript, payload.region)
    score = voice_service.score_categories(categories)
    verdict = voice_service.verdict_from_score(score)

    return VoiceAnalysisResponse(
        risk_score=score,
        verdict=verdict,
        categories=categories,
    )


@app.get("/", tags=["system"])
def root() -> dict:
    return {
        "service": "ScamShield AI",
        "docs": "/docs",
        "health": "/api/health",
    }
