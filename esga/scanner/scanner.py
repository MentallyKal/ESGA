"""
Scan orchestrator: coordinates parsing, rule evaluation, and result storage.
"""

from sqlalchemy.orm import Session

from esga.models import Finding, RiskScore, Rule, Scan
from esga.parser.terraform import parse_tf_file
from esga.rules.engine import evaluate_resource
from esga.scanner.scoring import compute_risk_score


def run_scan(db: Session, filename: str, file_content: str) -> Scan:
    """
    Execute a full scan on a .tf file.

    Steps:
      1. Parse the file into resource tuples.
      2. Load all enabled rules from the database.
      3. Evaluate each resource against each applicable rule.
      4. Compute the risk score from all findings.
      5. Persist Scan, Finding, and RiskScore records.

    Args:
        db: SQLAlchemy session
        filename: Original uploaded filename
        file_content: The raw .tf file content

    Returns:
        The created Scan ORM object (with relationships loaded).
    """
    # Step 1: Parse
    resources = parse_tf_file(file_content)

    # Step 2: Load rules
    rules = db.query(Rule).filter(Rule.enabled == True).all()  # noqa: E712

    # Step 3: Evaluate
    all_findings: list[dict] = []
    for resource_type, resource_name, attrs in resources:
        findings = evaluate_resource(
            resource_type=resource_type,
            resource_name=resource_name,
            attrs=attrs,
            rules=rules,
            file_path=filename,
        )
        all_findings.extend(findings)

    # Step 4: Compute risk score
    score_data = compute_risk_score(all_findings)

    # Step 5: Persist
    scan = Scan(
        filename=filename,
        status="completed",
        total_resources=len(resources),
        total_findings=len(all_findings),
    )
    db.add(scan)
    db.flush()  # Get scan.id

    for f in all_findings:
        finding = Finding(
            scan_id=scan.id,
            rule_id=f["rule_db_id"],
            resource_name=f["resource_name"],
            resource_type=f["resource_type"],
            severity=f["severity"],
            message=f["message"],
            file_path=f["file_path"],
        )
        db.add(finding)

    risk_score = RiskScore(
        scan_id=scan.id,
        score=score_data["score"],
        critical_count=score_data["critical_count"],
        high_count=score_data["high_count"],
        medium_count=score_data["medium_count"],
        low_count=score_data["low_count"],
        grade=score_data["grade"],
    )
    db.add(risk_score)

    db.commit()
    db.refresh(scan)
    return scan
