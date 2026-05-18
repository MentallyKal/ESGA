"""Tests for the risk scoring algorithm."""

from esga.scanner.scoring import compute_risk_score


def test_zero_findings():
    result = compute_risk_score([])
    assert result["score"] == 0.0
    assert result["grade"] == "A"
    assert result["critical_count"] == 0
    assert result["high_count"] == 0


def test_single_critical():
    findings = [{"severity": "CRITICAL"}]
    result = compute_risk_score(findings)
    assert result["score"] == 25.0
    assert result["grade"] == "B"
    assert result["critical_count"] == 1


def test_four_criticals_cap_at_100():
    findings = [{"severity": "CRITICAL"}] * 4
    result = compute_risk_score(findings)
    assert result["score"] == 100.0
    assert result["grade"] == "F"


def test_five_criticals_still_100():
    findings = [{"severity": "CRITICAL"}] * 5
    result = compute_risk_score(findings)
    assert result["score"] == 100.0


def test_mixed_severity():
    findings = [
        {"severity": "CRITICAL"},  # 25
        {"severity": "HIGH"},      # 15
        {"severity": "MEDIUM"},    # 8
        {"severity": "LOW"},       # 3
    ]
    result = compute_risk_score(findings)
    assert result["score"] == 51.0  # 25 + 15 + 8 + 3
    assert result["grade"] == "D"
    assert result["critical_count"] == 1
    assert result["high_count"] == 1
    assert result["medium_count"] == 1
    assert result["low_count"] == 1


def test_grade_a_boundary():
    # 3 LOW = 9 points -> grade A
    findings = [{"severity": "LOW"}] * 3
    result = compute_risk_score(findings)
    assert result["score"] == 9.0
    assert result["grade"] == "A"


def test_grade_b_boundary():
    # 1 CRITICAL + 0 = 25 -> grade B
    findings = [{"severity": "CRITICAL"}]
    result = compute_risk_score(findings)
    assert result["score"] == 25.0
    assert result["grade"] == "B"


def test_grade_c_boundary():
    # 2 CRITICAL = 50 -> grade C
    findings = [{"severity": "CRITICAL"}] * 2
    result = compute_risk_score(findings)
    assert result["score"] == 50.0
    assert result["grade"] == "C"


def test_grade_d_boundary():
    # 3 CRITICAL = 75 -> grade D
    findings = [{"severity": "CRITICAL"}] * 3
    result = compute_risk_score(findings)
    assert result["score"] == 75.0
    assert result["grade"] == "D"


def test_all_low():
    # 4 LOW = 12 -> grade B
    findings = [{"severity": "LOW"}] * 4
    result = compute_risk_score(findings)
    assert result["score"] == 12.0
    assert result["grade"] == "B"
