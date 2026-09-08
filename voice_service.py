"""
ScamShield AI — Voice / Call Transcript Urgency Classifier

Like qr_service.py, this is a transparent keyword-and-pattern heuristic
engine rather than a trained model — it looks for the same rhetorical
moves that show up again and again in scam call scripts (impersonating
authority, manufacturing urgency, steering toward untraceable payment,
and demanding secrecy) and explains exactly which phrases tripped it.

It classifies text a person has already chosen to analyze; it does not
listen in on or transcribe calls itself.
"""

import re
from typing import Dict, List, Optional

from app.models import VoiceCategoryHit

# Each category: (label, weight-per-hit, capped weight, phrase list)
CATEGORIES: Dict[str, Dict] = {
    "authority_impersonation": {
        "label": "Impersonating a government agency, bank, or well-known company",
        "weight": 25,
        "cap": 50,
        "phrases": [
            "irs", "social security administration", "medicare", "arrest warrant",
            "federal agent", "the sheriff", "fraud department", "amazon security",
            "microsoft support", "apple support", "your bank's fraud team",
            "court order", "final legal notice",
        ],
    },
    "urgency_pressure": {
        "label": "Manufactured urgency meant to stop you from thinking it through",
        "weight": 15,
        "cap": 30,
        "phrases": [
            "act now", "immediately", "right away", "within the hour",
            "before it's too late", "final notice", "last warning",
            "your account will be closed", "you will be arrested",
            "time-sensitive", "act today",
        ],
    },
    "untraceable_payment": {
        "label": "Requests payment through untraceable or hard-to-reverse methods",
        "weight": 30,
        "cap": 60,
        "phrases": [
            "gift card", "itunes card", "google play card", "wire transfer",
            "western union", "moneygram", "bitcoin", "cryptocurrency",
            "crypto atm", "prepaid card", "cash app", "zelle transfer",
        ],
    },
    "secrecy_isolation": {
        "label": "Asking you to keep the call secret or avoid verifying with others",
        "weight": 25,
        "cap": 50,
        "phrases": [
            "don't tell anyone", "keep this confidential", "don't hang up",
            "stay on the line", "don't tell your family", "this is confidential",
            "do not call anyone else",
        ],
    },
    "credential_harvesting": {
        "label": "Directly requesting sensitive personal or account information",
        "weight": 20,
        "cap": 40,
        "phrases": [
            "verify your social security number", "confirm your password",
            "your pin number", "one-time passcode", "verification code",
            "your card number", "your account number", "your date of birth",
            "security question",
        ],
    },
}


def _find_phrases(transcript_lower: str, phrases: List[str]) -> List[str]:
    hits = []
    for phrase in phrases:
        if re.search(re.escape(phrase), transcript_lower):
            hits.append(phrase)
    return hits


def analyze_transcript(transcript: str, region: Optional[str] = None) -> List[VoiceCategoryHit]:
    text_lower = transcript.lower()
    results: List[VoiceCategoryHit] = []

    for code, cfg in CATEGORIES.items():
        matched = _find_phrases(text_lower, cfg["phrases"])
        if matched:
            weight = min(cfg["cap"], cfg["weight"] * len(matched))
            results.append(VoiceCategoryHit(
                category=code,
                label=cfg["label"],
                matched_phrases=matched,
                weight=weight,
            ))

    return results


def score_categories(categories: List[VoiceCategoryHit]) -> int:
    return min(100, sum(c.weight for c in categories))


def verdict_from_score(score: int) -> str:
    if score >= 55:
        return "danger"
    if score >= 20:
        return "caution"
    return "safe"
