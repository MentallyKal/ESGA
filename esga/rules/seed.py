"""Seed security rules into the database on first startup."""

from sqlalchemy.orm import Session

from esga.models import Rule
from esga.rules.definitions import SECURITY_RULES


def seed_rules(db: Session) -> int:
    """
    Insert all rules from SECURITY_RULES into the database if they
    do not already exist (matched by rule_id).

    Returns the count of newly inserted rules.
    """
    inserted = 0
    for rule_def in SECURITY_RULES:
        existing = db.query(Rule).filter(Rule.rule_id == rule_def["rule_id"]).first()
        if existing is None:
            rule = Rule(
                rule_id=rule_def["rule_id"],
                name=rule_def["name"],
                description=rule_def["description"],
                resource_type=rule_def["resource_type"],
                severity=rule_def["severity"],
                attribute_path=rule_def["attribute_path"],
                condition=rule_def["condition"],
                expected_value=rule_def.get("expected_value"),
                enabled=True,
            )
            db.add(rule)
            inserted += 1
    db.commit()
    return inserted
