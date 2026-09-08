"""
ScamShield AI — QR / Link Vision Heuristic Engine

This module never fetches the target URL. Everything here is a static,
offline heuristic over the decoded text of a QR code, so scanning a
malicious code can never trigger a real network request from the server.

Each heuristic contributes a weighted "finding" to a running risk score
from 0 (looks fine) to 100 (near-certain scam). This is intentionally a
transparent, explainable rules engine rather than a black box — every
point on the score maps to a specific, named reason a person can read.
"""

import re
from typing import List, Optional
from urllib.parse import urlparse

from app.models import QRFinding

# Common, legitimate URL shorteners are *not* inherently malicious, but
# scammers lean on them heavily to hide the real destination, so they add
# a moderate amount of risk rather than an automatic "danger" verdict.
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".club", ".gq", ".tk", ".work",
    ".loan", ".men", ".click", ".country", ".stream", ".gdn",
}

# Frequently-impersonated brands. If the domain contains the brand name but
# isn't the brand's actual registered domain, that's classic typosquatting.
IMPERSONATION_TARGETS = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "usps": {"usps.com"},
    "irs": {"irs.gov"},
    "bankofamerica": {"bankofamerica.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "google": {"google.com", "gmail.com"},
    "docusign": {"docusign.com", "docusign.net"},
}

URGENCY_KEYWORDS = (
    "verify", "confirm", "suspend", "locked", "urgent", "immediately",
    "reactivate", "limited", "expire", "restricted", "unusual-activity",
)

IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Matches a bare domain with an optional path, e.g. "bit.ly/3xYzAbC" or
# "paypal-secure.top", so links pasted or decoded without a scheme are
# still recognized as URLs instead of falling through to plain-text checks.
DOMAIN_LIKE_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
    r"(?:[/?#]\S*)?$"
)


def _weighted(code: str, label: str, weight: int) -> QRFinding:
    return QRFinding(code=code, label=label, weight=weight)


def analyze_qr_content(content: str, region: Optional[str] = None) -> List[QRFinding]:
    """Run every heuristic against the decoded QR payload and return the
    list of findings that fired. An empty list means nothing looked wrong."""
    findings: List[QRFinding] = []
    text = content.strip()

    # Not even a URL — could be plain text, wifi config, a contact card,
    # etc. Those are out of scope for link heuristics, so bail out early.
    looks_like_url = bool(URL_SCHEME_RE.match(text)) or bool(DOMAIN_LIKE_RE.match(text))
    if not looks_like_url:
        if any(k in text.lower() for k in URGENCY_KEYWORDS):
            findings.append(_weighted(
                "urgency_language_plaintext",
                "Contains urgent/scare language typical of scam QR payloads",
                20,
            ))
        return findings

    normalized = text if "://" in text else f"http://{text}"
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()

    if parsed.scheme == "http":
        findings.append(_weighted("no_https", "Link does not use a secure HTTPS connection", 15))

    if "@" in normalized.split("://", 1)[-1].split("/")[0]:
        findings.append(_weighted(
            "at_symbol_obfuscation",
            "Contains an '@' before the domain — a classic trick to disguise the real destination",
            30,
        ))

    if host and IP_HOST_RE.match(host):
        findings.append(_weighted("raw_ip_host", "Points directly to a raw IP address instead of a named domain", 35))

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(_weighted(
            "punycode_domain",
            "Uses Punycode encoding, often used to mimic a trusted brand with look-alike characters",
            35,
        ))

    if host in KNOWN_SHORTENERS:
        findings.append(_weighted(
            "url_shortener",
            "Uses a link shortener, which hides the real destination until after you click",
            15,
        ))

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            findings.append(_weighted("suspicious_tld", f"Uses the '{tld}' domain ending, disproportionately common in scam campaigns", 15))
            break

    subdomain_count = max(host.count("."), 0)
    if subdomain_count >= 4:
        findings.append(_weighted(
            "excessive_subdomains",
            "Unusually long chain of subdomains, often used to bury a fake brand name",
            20,
        ))

    if len(text) > 120:
        findings.append(_weighted("excessive_length", "Unusually long link, which can hide redirect parameters", 10))

    for brand, real_domains in IMPERSONATION_TARGETS.items():
        if brand in host.replace("-", "").replace(".", "") and host not in real_domains:
            if not any(host.endswith(f".{d}") or host == d for d in real_domains):
                findings.append(_weighted(
                    "brand_impersonation",
                    f"Domain references '{brand.title()}' but is not an official {brand.title()} domain",
                    40,
                ))
                break

    path_and_query = (parsed.path + "?" + parsed.query).lower()
    hit_keywords = [k for k in URGENCY_KEYWORDS if k in path_and_query or k in host]
    if hit_keywords:
        findings.append(_weighted(
            "urgency_language_url",
            "URL contains pressure language (e.g. 'verify', 'suspended') typical of phishing links",
            20,
        ))

    return findings


def score_findings(findings: List[QRFinding]) -> int:
    return min(100, sum(f.weight for f in findings))


def verdict_from_score(score: int) -> str:
    if score >= 60:
        return "danger"
    if score >= 25:
        return "caution"
    return "safe"
