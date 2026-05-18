"""API endpoints for rule operations."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from esga.database import get_db
from esga.models import Rule
from esga.schemas import RuleOut

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("/", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db)) -> list[Rule]:
    """List all security rules."""
    return db.query(Rule).order_by(Rule.severity, Rule.rule_id).all()
