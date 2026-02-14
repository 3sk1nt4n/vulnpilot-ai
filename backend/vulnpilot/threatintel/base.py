"""
VulnPilot AI - Threat Intelligence Provider Interface (Layer 4)
Switch between live API calls (production) and cached local files (free dev).

THREATINTEL_MODE=local → Cached CSV/JSON files ($0)
THREATINTEL_MODE=api   → Live EPSS/KEV/OTX/GreyNoise APIs
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ThreatIntelResult:
    """Enriched threat intelligence for a single CVE."""

    cve_id: str

    # --- EPSS (25% of VPRS) ---
    epss_score: float = 0.0             # 0-1 probability of exploitation in 30 days
    epss_percentile: float = 0.0        # 0-100 percentile rank

    # --- CISA KEV (20% of VPRS) ---
    in_kev: bool = False                # Is this CVE in the CISA KEV catalog?
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_ransomware_use: str = "Unknown" # Known, Unknown

    # --- Dark Web Intelligence (15% of VPRS) ---
    dark_web_mentions: int = 0          # Count of dark web references
    exploit_available: bool = False      # Is a weaponized exploit publicly available?
    exploit_for_sale: bool = False       # Is an exploit being sold on dark web?
    ransomware_associated: bool = False  # Associated with ransomware campaigns?
    active_scanning: bool = False        # Detected in GreyNoise active scanning?

    # --- Sources Used ---
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "in_kev": self.in_kev,
            "kev_date_added": self.kev_date_added,
            "kev_ransomware_use": self.kev_ransomware_use,
            "dark_web_mentions": self.dark_web_mentions,
            "exploit_available": self.exploit_available,
            "exploit_for_sale": self.exploit_for_sale,
            "ransomware_associated": self.ransomware_associated,
            "active_scanning": self.active_scanning,
            "sources": self.sources,
        }


class ThreatIntelProvider(ABC):
    """
    Abstract base class for threat intelligence providers.
    Implementations: LocalThreatIntel (cached files), APIThreatIntel (live APIs)
    """

    @abstractmethod
    async def enrich(self, cve_id: str) -> ThreatIntelResult:
        """Get full threat intelligence enrichment for a CVE.

        Queries EPSS, KEV, dark web, and active scanning data.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-21887)

        Returns:
            ThreatIntelResult with all enrichment data
        """
        ...

    @abstractmethod
    async def get_epss(self, cve_id: str) -> float:
        """Get EPSS score for a CVE (0-1 probability).

        Source: FIRST.org EPSS API or cached CSV
        """
        ...

    @abstractmethod
    async def is_in_kev(self, cve_id: str) -> bool:
        """Check if CVE is in the CISA KEV catalog.

        Source: CISA KEV JSON feed
        """
        ...

    @abstractmethod
    async def get_dark_web_intel(self, cve_id: str) -> dict:
        """Get dark web / threat intel signals.

        Sources: AlienVault OTX, abuse.ch, GreyNoise
        """
        ...

    @abstractmethod
    async def refresh_cache(self) -> bool:
        """Refresh local cache of EPSS/KEV/threat intel data.
        Called by Celery beat on schedule.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if threat intel sources are available."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return provider name ('local' or 'api')."""
        ...
