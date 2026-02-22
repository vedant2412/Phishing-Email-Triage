from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .features import FeatureResult


@dataclass
class ScoreResult:
    score: int
    classification: str
    reasons: List[str]


def _clamp(n: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, n))


def score_email(features: List[FeatureResult]) -> ScoreResult:
    """
    Convert detected features into an explainable risk score (0–100).

    Scoring model (simple, realistic):
    - Each feature has a severity 1–5
    - We map severity to points and sum
    - Then clamp to 0–100 and classify
    """
    # Severity -> points mapping (tunable)
    severity_points = {
        1: 8,
        2: 12,
        3: 18,
        4: 25,
        5: 35,
    }

    points = 0
    reasons: List[str] = []

    for f in features:
        pts = severity_points.get(int(f.severity), 10)
        points += pts
        reasons.append(f.description)

    score = _clamp(points)

    # Classification thresholds
    if score >= 70:
        classification = "Likely Phishing"
    elif score >= 35:
        classification = "Suspicious"
    else:
        classification = "Safe"

    return ScoreResult(score=score, classification=classification, reasons=reasons)