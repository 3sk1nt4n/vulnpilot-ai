"""
VulnPilot AI - API Schemas (Pydantic)
Request and response models for the REST API.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


# ============================================================
# Health / Status
# ============================================================

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    llm_provider: str
    scanner_providers: list[str]
    ticket_provider: str
    threatintel_mode: str
    mode: str  # "local" or "cloud"


class ProviderStatus(BaseModel):
    name: str
    healthy: bool
    error: Optional[str] = None


class SystemStatus(BaseModel):
    llm: ProviderStatus
    scanners: list[ProviderStatus]
    ticket: ProviderStatus
    threatintel: ProviderStatus
    database: ProviderStatus


# ============================================================
# VPRS Scoring
# ============================================================

class VPRSComponentsResponse(BaseModel):
    epss: dict = Field(description="EPSS factor (raw + weighted)")
    kev: dict = Field(description="KEV factor (match + weighted)")
    dark_web: dict = Field(description="Dark web factor (score + weighted)")
    asset: dict = Field(description="Asset criticality (score + weighted)")
    reachability: dict = Field(description="Reachability (score + weighted)")
    controls: dict = Field(description="Controls (score + weighted)")


class VPRSScoreResponse(BaseModel):
    cve_id: str
    vprs_score: float = Field(ge=0, le=100)
    severity: str
    components: VPRSComponentsResponse
    hard_rule_triggered: bool = False
    hard_rule_name: Optional[str] = None
    weights_used: dict
    sla_hours: int
    priority: str
    justification: Optional[str] = None
    debate_applied: bool = False


# ============================================================
# Vulnerability Input
# ============================================================

class VulnerabilityInput(BaseModel):
    """Manual vulnerability input for scoring."""
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss_base_score: float = Field(ge=0, le=10, default=0.0)
    title: str = ""
    hostname: str = ""
    ip_address: str = ""
    port: int = 0
    asset_tier: str = Field(default="tier_3", pattern=r"^tier_[123]$")
    is_internet_facing: bool = False
    has_waf: bool = False
    has_ips: bool = False
    is_segmented: bool = False
    owner: str = ""
    business_unit: str = ""


class BatchScoreRequest(BaseModel):
    """Request to score multiple CVEs at once."""
    vulnerabilities: list[VulnerabilityInput]


# ============================================================
# Pipeline Results
# ============================================================

class PipelineResultResponse(BaseModel):
    cve_id: str
    vprs_score: float
    severity: str
    epss_score: float
    in_kev: bool
    hard_rule_triggered: bool
    debate_applied: bool
    ticket_created: bool
    ticket_id: Optional[str] = None
    justification_summary: Optional[str] = None
    processing_time_ms: float


class BatchResultResponse(BaseModel):
    total_input: int
    noise_eliminated: int
    noise_elimination_rate: float
    tickets_created: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    hard_rules_triggered: int
    adversarial_overrides: int
    processing_time_seconds: float
    results: list[PipelineResultResponse]


# ============================================================
# Configuration
# ============================================================

class WeightsResponse(BaseModel):
    epss: float
    kev: float
    dark_web: float
    asset_criticality: float
    reachability: float
    controls: float

class WeightsUpdateRequest(BaseModel):
    epss: float = Field(ge=0, le=1)
    kev: float = Field(ge=0, le=1)
    dark_web: float = Field(ge=0, le=1)
    asset_criticality: float = Field(ge=0, le=1)
    reachability: float = Field(ge=0, le=1)
    controls: float = Field(ge=0, le=1)
