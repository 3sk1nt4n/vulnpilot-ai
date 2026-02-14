"""
VulnPilot AI - Scanner Provider Interface (Layer 2)
Supports multiple simultaneous scanners (scanner-agnostic architecture).
All scanner data normalizes to NormalizedVuln before VPRS scoring.

SCANNER_PROVIDERS=tenable,qualys  → Multiple scanners at once
SCANNER_PROVIDERS=openvas         → Free local scanning
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class NormalizedVuln:
    """Unified vulnerability schema - the bridge between any scanner and VPRS.
    Doesn't matter if it came from Tenable API or OpenVAS XML.
    Same format, same scoring, same output.
    """

    # --- Identifiers ---
    cve_id: str                              # CVE-2024-XXXXX
    source_scanner: str                      # tenable, qualys, openvas, nessus_file
    source_id: str = ""                      # Scanner's internal plugin/QID/NVT ID

    # --- CVSS (from scanner) ---
    cvss_base_score: float = 0.0
    cvss_vector: str = ""
    cvss_version: str = "3.1"

    # --- Vulnerability Details ---
    title: str = ""
    description: str = ""
    solution: str = ""
    cwe_id: str = ""
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None

    # --- Affected Asset ---
    hostname: str = ""
    ip_address: str = ""
    port: int = 0
    protocol: str = ""
    os: str = ""
    software: str = ""                       # Affected software name + version

    # --- Asset Context (enriched later) ---
    asset_tier: str = "tier_3"               # tier_1, tier_2, tier_3
    is_internet_facing: bool = False
    business_unit: str = ""
    owner: str = ""
    owner_email: str = ""

    # --- Compensating Controls ---
    has_waf: bool = False
    has_ips: bool = False
    is_segmented: bool = False

    # --- Raw Scanner Data (preserved for audit) ---
    raw_data: dict = field(default_factory=dict)

    # --- Metadata ---
    ingested_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization and LLM context."""
        return {
            "cve_id": self.cve_id,
            "source_scanner": self.source_scanner,
            "cvss_base_score": self.cvss_base_score,
            "cvss_vector": self.cvss_vector,
            "title": self.title,
            "description": self.description[:500],  # Truncate for LLM context
            "solution": self.solution[:500],
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "port": self.port,
            "asset_tier": self.asset_tier,
            "is_internet_facing": self.is_internet_facing,
            "has_waf": self.has_waf,
            "has_ips": self.has_ips,
            "is_segmented": self.is_segmented,
            "owner": self.owner,
            "business_unit": self.business_unit,
        }


class ScannerProvider(ABC):
    """
    Abstract base class for vulnerability scanner providers.
    Implementations: TenableProvider, QualysProvider, Rapid7Provider,
                     OpenVASProvider, NessusFileProvider
    """

    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the scanner.
        Returns True if connection is successful.
        """
        ...

    @abstractmethod
    async def fetch_vulnerabilities(
        self, since: Optional[datetime] = None
    ) -> list[NormalizedVuln]:
        """Fetch vulnerability findings and normalize to NormalizedVuln.

        Args:
            since: Only fetch vulns modified after this datetime (incremental)

        Returns:
            List of NormalizedVuln records ready for VPRS scoring
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the scanner is reachable and authenticated."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return scanner name (e.g., 'tenable', 'openvas')."""
        ...
