"""API endpoint for dashboard summary data."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from esga.database import get_db
from esga.models import Finding, RiskScore, Scan
from esga.schemas import DashboardSummary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummary:
    """Aggregated risk data for the dashboard."""

    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    total_findings = db.query(func.count(Finding.id)).scalar() or 0

    avg_score = db.query(func.avg(RiskScore.score)).scalar() or 0.0
    worst_score = db.query(func.max(RiskScore.score)).scalar() or 0.0
    best_score = db.query(func.min(RiskScore.score)).scalar() or 0.0

    # Severity breakdown across ALL findings
    severity_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )
    severity_counts: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    for sev, count in severity_rows:
        severity_counts[sev] = count

    # Grade distribution
    grade_rows = (
        db.query(RiskScore.grade, func.count(RiskScore.id))
        .group_by(RiskScore.grade)
        .all()
    )
    grade_distribution: dict[str, int] = {}
    for grade, count in grade_rows:
        grade_distribution[grade] = count

    # Recent scans (last 10)
    recent_scans = (
        db.query(Scan)
        .options(joinedload(Scan.risk_score))
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    return DashboardSummary(
        total_scans=total_scans,
        total_findings=total_findings,
        average_score=round(float(avg_score), 1),
        worst_score=round(float(worst_score), 1),
        best_score=round(float(best_score), 1),
        severity_counts=severity_counts,
        recent_scans=recent_scans,
        grade_distribution=grade_distribution,
    )
