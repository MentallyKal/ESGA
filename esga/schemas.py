from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


# --- Rule schemas ---
class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    name: str
    description: str
    resource_type: str
    severity: str
    attribute_path: str
    condition: str
    expected_value: str | None
    enabled: bool


# --- Finding schemas ---
class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: int
    resource_name: str
    resource_type: str
    severity: str
    message: str
    file_path: str | None
    created_at: datetime


# --- RiskScore schemas ---
class RiskScoreOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    grade: str


# --- Scan schemas ---
class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    status: str
    total_resources: int
    total_findings: int
    created_at: datetime
    risk_score: RiskScoreOut | None


class ScanDetail(ScanSummary):
    findings: list[FindingOut]


# --- Dashboard schemas ---
class DashboardSummary(BaseModel):
    total_scans: int
    total_findings: int
    average_score: float
    worst_score: float
    best_score: float
    severity_counts: dict[str, int]
    recent_scans: list[ScanSummary]
    grade_distribution: dict[str, int]
