"""
Risk score computation: 0 (clean) to 100 (maximum risk).

Algorithm:
  1. Each finding contributes severity-weighted points:
       CRITICAL = 25, HIGH = 15, MEDIUM = 8, LOW = 3

  2. Raw score = sum of all finding points.

  3. Normalized score = min(100, raw_score).

  4. Grade mapping:
       0-10   -> A  (Excellent)
       11-25  -> B  (Good)
       26-50  -> C  (Fair)
       51-75  -> D  (Poor)
       76-100 -> F  (Failing)
"""

from __future__ import annotations

from typing import Any

SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
}

GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (10, "A"),
    (25, "B"),
    (50, "C"),
    (75, "D"),
    (100, "F"),
]


def compute_risk_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute the risk score from a list of findings.

    Args:
        findings: list of finding dicts, each with a "severity" key.

    Returns:
        dict with keys: score, critical_count, high_count,
        medium_count, low_count, grade
    """
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in counts:
            counts[sev] += 1

    raw_score = sum(counts[sev] * SEVERITY_WEIGHTS[sev] for sev in counts)
    normalized_score = min(100.0, float(raw_score))

    grade = "F"
    for threshold, g in GRADE_THRESHOLDS:
        if normalized_score <= threshold:
            grade = g
            break

    return {
        "score": normalized_score,
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
        "grade": grade,
    }
