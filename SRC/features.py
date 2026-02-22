from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from .parser import ParsedEmail
from .iocs import IOCs


@dataclass
class FeatureResult:
    name: str
    description: str
    severity: int  # 1 (low) to 5 (high)


# Urgency / coercion keywords (very common in phishing)
URGENCY_PATTERNS = [
    r"verify your account",
    r"urgent action required",
    r"immediately",
    r"account suspended",
    r"password expires",
    r"confirm your identity",
    r"click below",
    r"invoice attached",
    r"payment failed",
]

DOUBLE_EXTENSION_RE = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|png)\.exe$", re.IGNORECASE)


def detect_features(email: ParsedEmail, iocs: IOCs) -> List[FeatureResult]:
    """
    Detect phishing-related indicators from parsed email + extracted IOCs.
    Returns a list of detected features (no scoring yet).
    """

    findings: List[FeatureResult] = []

    # -----------------------------
    # 1. From vs Reply-To mismatch
    # -----------------------------
    if email.from_addr and email.reply_to:
        if email.from_addr.lower() not in email.reply_to.lower():
            findings.append(
                FeatureResult(
                    name="from_replyto_mismatch",
                    description="Sender and Reply-To addresses differ.",
                    severity=4,
                )
            )

    # -----------------------------
    # 2. Return-Path mismatch
    # -----------------------------
    if email.from_addr and email.return_path:
        if email.from_addr.lower() not in email.return_path.lower():
            findings.append(
                FeatureResult(
                    name="return_path_mismatch",
                    description="Return-Path differs from From address.",
                    severity=3,
                )
            )

    # -----------------------------
    # 3. IP-based URLs
    # -----------------------------
    for url in iocs.urls:
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
            findings.append(
                FeatureResult(
                    name="ip_in_url",
                    description="URL uses raw IP address instead of domain.",
                    severity=5,
                )
            )
            break

    # -----------------------------
    # 4. Suspicious TLDs
    # -----------------------------
    suspicious_tlds = [".xyz", ".top", ".gq", ".tk", ".cf", ".ru"]
    for d in iocs.domains:
        if any(d.endswith(tld) for tld in suspicious_tlds):
            findings.append(
                FeatureResult(
                    name="suspicious_tld",
                    description=f"Domain uses high-risk TLD: {d}",
                    severity=3,
                )
            )
            break

    # -----------------------------
    # 5. Urgency language
    # -----------------------------
    body_lower = email.body_text.lower()

    for pattern in URGENCY_PATTERNS:
        if pattern in body_lower:
            findings.append(
                FeatureResult(
                    name="urgency_language",
                    description=f"Urgent or coercive language detected: '{pattern}'",
                    severity=3,
                )
            )
            break

    # -----------------------------
    # 6. Suspicious attachment hints
    # -----------------------------
    content_disposition = email.headers.get("content-disposition", "").lower()
    if DOUBLE_EXTENSION_RE.search(content_disposition):
        findings.append(
            FeatureResult(
                name="double_extension_attachment",
                description="Attachment contains suspicious double file extension.",
                severity=5,
            )
        )

    # -----------------------------
    # 7. Excessive links
    # -----------------------------
    if len(iocs.urls) >= 5:
        findings.append(
            FeatureResult(
                name="excessive_links",
                description="Email contains unusually high number of URLs.",
                severity=2,
            )
        )

    return findings