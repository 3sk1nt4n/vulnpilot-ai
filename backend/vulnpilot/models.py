"""
VulnPilot AI - Database Models (SQLAlchemy ORM)
Same schema works on Docker Postgres (local) and AWS RDS (production).
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, String, Float, Integer, Boolean, DateTime, Text,
    ForeignKey, Enum, JSON, Index, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


# ============================================================
# Enums
# ============================================================

class VPRSSeverity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TicketStatus(str, PyEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"


class SLAStatus(str, PyEnum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"       # > 50% SLA elapsed
    WARNING = "warning"       # > 75% SLA elapsed
    BREACHED = "breached"


class AssetTier(str, PyEnum):
    TIER_1 = "tier_1"  # Crown jewels (payment, auth, PII)
    TIER_2 = "tier_2"  # Important (internal apps, dev infra)
    TIER_3 = "tier_3"  # Standard (workstations, printers)


# ============================================================
# Core Tables
# ============================================================

class Vulnerability(Base):
    """Normalized vulnerability record from any scanner."""
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(20), nullable=False, index=True)  # CVE-2024-XXXXX
    source_scanner = Column(String(50), nullable=False)       # tenable, qualys, openvas
    source_id = Column(String(100))                           # Scanner's internal ID

    # --- CVSS Data (from scanner) ---
    cvss_base_score = Column(Float, default=0.0)
    cvss_vector = Column(String(200))
    cvss_version = Column(String(10), default="3.1")

    # --- Vulnerability Details ---
    title = Column(String(500), nullable=False)
    description = Column(Text)
    solution = Column(Text)
    cwe_id = Column(String(20))                               # CWE-79, CWE-89, etc.
    published_date = Column(DateTime)
    last_modified = Column(DateTime)

    # --- Asset Info ---
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    hostname = Column(String(255))
    ip_address = Column(String(45))
    port = Column(Integer)
    protocol = Column(String(10))

    # --- Raw Scanner Output ---
    raw_data = Column(JSON)

    # --- Metadata ---
    ingested_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # --- Relationships ---
    asset = relationship("Asset", back_populates="vulnerabilities")
    vprs_scores = relationship("VPRSScore", back_populates="vulnerability", cascade="all, delete-orphan")
    tickets = relationship("Ticket", back_populates="vulnerability")

    __table_args__ = (
        UniqueConstraint("cve_id", "source_scanner", "ip_address", "port", name="uq_vuln_source_asset"),
        Index("ix_vuln_cve_id", "cve_id"),
        Index("ix_vuln_ingested", "ingested_at"),
    )


class Asset(Base):
    """Asset inventory - maps to customer CMDB."""
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), index=True)
    os = Column(String(200))
    tier = Column(Enum(AssetTier), default=AssetTier.TIER_3)
    is_internet_facing = Column(Boolean, default=False)
    business_unit = Column(String(200))
    owner = Column(String(200))                              # Team or person
    owner_email = Column(String(254))

    # --- Compensating Controls ---
    has_waf = Column(Boolean, default=False)
    has_ips = Column(Boolean, default=False)
    is_segmented = Column(Boolean, default=False)
    additional_controls = Column(JSON, default=dict)

    # --- Metadata ---
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # --- Relationships ---
    vulnerabilities = relationship("Vulnerability", back_populates="asset")


class VPRSScore(Base):
    """VulnPilot Risk Score - the core scoring output."""
    __tablename__ = "vprs_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False)

    # --- VPRS Score (0-100) ---
    vprs_score = Column(Float, nullable=False)
    severity = Column(Enum(VPRSSeverity), nullable=False)

    # --- 6 Factor Components ---
    epss_score = Column(Float, default=0.0)          # Raw EPSS (0-1)
    epss_component = Column(Float, default=0.0)      # Weighted contribution
    kev_match = Column(Boolean, default=False)
    kev_component = Column(Float, default=0.0)
    dark_web_mentions = Column(Integer, default=0)
    dark_web_component = Column(Float, default=0.0)
    asset_criticality = Column(Float, default=0.0)   # Tier-based (0-100)
    asset_component = Column(Float, default=0.0)
    reachability_score = Column(Float, default=0.0)  # 0-100
    reachability_component = Column(Float, default=0.0)
    controls_score = Column(Float, default=0.0)      # 0-100 (higher = more protected)
    controls_component = Column(Float, default=0.0)

    # --- Weights Used (for audit trail) ---
    weights_used = Column(JSON)

    # --- Hard Rules (Lock 1) ---
    hard_rule_triggered = Column(Boolean, default=False)
    hard_rule_name = Column(String(200))
    hard_rule_override_score = Column(Float)

    # --- Adversarial AI (Lock 2) ---
    justifier_score = Column(Float)        # Agent 3A's proposed score
    challenger_score = Column(Float)       # Agent 3B's counter-score
    debate_reasoning = Column(Text)        # Full debate transcript
    adversarial_override = Column(Boolean, default=False)

    # --- Justification ---
    justification = Column(Text)           # Plain-English Claude/Ollama output

    # --- Metadata ---
    scored_at = Column(DateTime, server_default=func.now())
    scoring_version = Column(String(20), default="1.0")
    llm_provider_used = Column(String(20))  # "ollama" or "anthropic"

    # --- Relationships ---
    vulnerability = relationship("Vulnerability", back_populates="vprs_scores")

    __table_args__ = (
        Index("ix_vprs_score", "vprs_score"),
        Index("ix_vprs_severity", "severity"),
        Index("ix_vprs_scored_at", "scored_at"),
    )


class Ticket(Base):
    """Remediation ticket tracking."""
    __tablename__ = "tickets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False)
    vprs_score_id = Column(UUID(as_uuid=True), ForeignKey("vprs_scores.id"))

    # --- Ticket Details ---
    external_id = Column(String(100))     # ServiceNow/Jira ticket number
    external_url = Column(String(500))
    provider = Column(String(50))          # servicenow, jira, console
    status = Column(Enum(TicketStatus), default=TicketStatus.OPEN)
    assigned_to = Column(String(200))
    assigned_email = Column(String(254))

    # --- SLA Tracking ---
    sla_deadline = Column(DateTime)
    sla_status = Column(Enum(SLAStatus), default=SLAStatus.ON_TRACK)
    sla_hours = Column(Integer)            # Total SLA hours

    # --- Escalation ---
    escalation_count = Column(Integer, default=0)
    last_escalated_at = Column(DateTime)
    nudge_count = Column(Integer, default=0)
    last_nudged_at = Column(DateTime)

    # --- Metadata ---
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    resolved_at = Column(DateTime)

    # --- Relationships ---
    vulnerability = relationship("Vulnerability", back_populates="tickets")

    __table_args__ = (
        Index("ix_ticket_status", "status"),
        Index("ix_ticket_sla", "sla_status"),
    )


class AuditLog(Base):
    """Immutable audit trail - every AI decision logged."""
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(100), nullable=False)  # score_calculated, ticket_created, etc.
    entity_type = Column(String(50))                   # vulnerability, ticket, asset
    entity_id = Column(UUID(as_uuid=True))
    cve_id = Column(String(20))

    # --- Event Data ---
    old_value = Column(JSON)
    new_value = Column(JSON)
    reasoning = Column(Text)                           # AI reasoning chain
    triggered_by = Column(String(100))                 # system, hard_rule, drift_detector, user

    # --- Metadata ---
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("ix_audit_event", "event_type"),
        Index("ix_audit_entity", "entity_type", "entity_id"),
        Index("ix_audit_created", "created_at"),
    )


class DriftEvent(Base):
    """Lock 3 - Drift detection events."""
    __tablename__ = "drift_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False)
    cve_id = Column(String(20), nullable=False)

    # --- What Changed ---
    drift_type = Column(String(50))  # epss_increase, kev_added, dark_web_new, greynoise_active
    old_vprs_score = Column(Float)
    new_vprs_score = Column(Float)
    old_severity = Column(String(20))
    new_severity = Column(String(20))

    # --- Details ---
    details = Column(JSON)
    auto_promoted = Column(Boolean, default=False)
    new_ticket_created = Column(Boolean, default=False)

    # --- Metadata ---
    detected_at = Column(DateTime, server_default=func.now())


# ============================================================
# Cloud Compliance Finding (Prowler / Custodian results)
# ============================================================

class CloudFinding(Base):
    """Persisted cloud compliance finding from Prowler or Cloud Custodian."""
    __tablename__ = "cloud_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Finding Identity ---
    check_id = Column(String(200), nullable=False, index=True)  # prowler-aws-iam_root_mfa
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(20), nullable=False, index=True)   # critical, high, medium, low
    severity_score = Column(Float, default=5.0)

    # --- Status ---
    status = Column(String(20), nullable=False, default="FAIL", index=True)  # PASS, FAIL, MANUAL
    status_detail = Column(Text, default="")

    # --- Compliance Mapping ---
    cloud_provider = Column(String(10), nullable=False, default="aws", index=True)
    frameworks = Column(JSON, default=list)     # ["CIS 1.5 - 1.6", "SOC2 CC6.1"]
    requirements = Column(JSON, default=list)   # raw requirement IDs

    # --- Affected Resource ---
    resource_type = Column(String(100), default="")  # AWS::IAM::User
    resource_id = Column(String(500), default="")     # ARN or resource ID
    resource_name = Column(String(200), default="")
    resource_region = Column(String(50), default="")
    account_id = Column(String(50), default="", index=True)

    # --- Remediation ---
    remediation = Column(Text, default="")
    remediation_url = Column(String(500), default="")

    # --- Scan Context ---
    scan_source = Column(String(50), default="prowler")  # prowler, custodian
    scan_timestamp = Column(DateTime)
    raw_ocsf = Column(JSON, default=dict)

    # --- Metadata ---
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_cloud_findings_check_account", "check_id", "account_id"),
        Index("ix_cloud_findings_severity_status", "severity", "status"),
    )
