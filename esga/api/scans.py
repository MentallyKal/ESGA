"""API endpoints for scan operations."""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session, joinedload

from esga.database import get_db
from esga.models import Scan
from esga.scanner.scanner import run_scan
from esga.schemas import ScanDetail, ScanSummary

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("/", response_model=ScanDetail, status_code=201)
async def create_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> Scan:
    """Upload a .tf file and run a security scan."""
    if not file.filename or not file.filename.endswith(".tf"):
        raise HTTPException(
            status_code=400,
            detail="Only .tf (Terraform) files are accepted.",
        )

    content = await file.read()
    file_content = content.decode("utf-8")

    try:
        scan = run_scan(db, file.filename, file_content)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Failed to parse Terraform file: {e}",
        )

    # Reload with relationships
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.findings), joinedload(Scan.risk_score))
        .filter(Scan.id == scan.id)
        .first()
    )
    return scan


@router.get("/", response_model=list[ScanSummary])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[Scan]:
    """List all scans, ordered by most recent first."""
    return (
        db.query(Scan)
        .options(joinedload(Scan.risk_score))
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    """Get full scan details including all findings."""
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.findings), joinedload(Scan.risk_score))
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
