import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from esga.database import Base


class Rule(Base):
    """A security rule definition stored in the database."""

    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    resource_type = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    attribute_path = Column(String(500), nullable=False)
    condition = Column(String(50), nullable=False)
    expected_value = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    findings = relationship("Finding", back_populates="rule")


class Scan(Base):
    """A single scan execution (one or more .tf files)."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(500), nullable=False)
    status = Column(String(20), nullable=False, default="completed")
    total_resources = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    risk_score = relationship(
        "RiskScore", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )


class Finding(Base):
    """A single security finding (violation) detected during a scan."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    rule_id = Column(Integer, ForeignKey("rules.id"), nullable=False)
    resource_name = Column(String(500), nullable=False)
    resource_type = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    file_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    rule = relationship("Rule", back_populates="findings")


class RiskScore(Base):
    """Computed risk score for a scan (0-100, higher = worse)."""

    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), unique=True, nullable=False)
    score = Column(Float, nullable=False)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    grade = Column(String(1), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="risk_score")
