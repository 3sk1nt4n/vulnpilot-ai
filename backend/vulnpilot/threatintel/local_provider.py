"""
VulnPilot AI - Local Threat Intelligence Provider
Reads from cached EPSS CSV + KEV JSON files. Zero API calls. $0 cost.
Download files once, score forever.

EPSS CSV: https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz
KEV JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import csv
import json
import logging
import os
from pathlib import Path

from vulnpilot.threatintel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger(__name__)


class LocalThreatIntelProvider(ThreatIntelProvider):
    """Offline threat intel using locally cached data files."""

    def __init__(self):
        self.epss_csv_path = os.getenv("EPSS_CSV_PATH", "./data/epss_scores.csv")
        self.kev_json_path = os.getenv("KEV_JSON_PATH", "./data/known_exploited_vulns.json")
        self.otx_pulse_path = os.getenv("OTX_PULSE_PATH", "./data/otx_pulses.json")

        # In-memory caches (loaded on first use)
        self._epss_cache: dict[str, dict] = {}
        self._kev_cache: set[str] = set()
        self._kev_data: dict[str, dict] = {}
        self._loaded = False
        self._fixtures_dir = Path(__file__).resolve().parent / "fixtures"
        self._epss_source = "epss_csv"
        self._kev_source = "kev_json"

    def _load_epss_file(self, path: Path) -> bool:
        try:
            with path.open("r") as f:
                reader = csv.DictReader(line for line in f if not line.startswith("#"))
                for row in reader:
                    cve = row.get("cve", "").strip()
                    if cve:
                        self._epss_cache[cve] = {
                            "score": float(row.get("epss", 0)),
                            "percentile": float(row.get("percentile", 0)) * 100,
                        }
            logger.info(f"Loaded {len(self._epss_cache)} EPSS scores from {path}")
            return True
        except Exception as e:
            logger.warning(f"Failed to load EPSS CSV from {path}: {e}")
            return False

    def _load_kev_file(self, path: Path) -> bool:
        try:
            with path.open("r") as f:
                data = json.load(f)
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve = v.get("cveID", "")
                    self._kev_cache.add(cve)
                    self._kev_data[cve] = {
                        "date_added": v.get("dateAdded"),
                        "due_date": v.get("dueDate"),
                        "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                    }
            logger.info(f"Loaded {len(self._kev_cache)} KEV entries from {path}")
            return True
        except Exception as e:
            logger.warning(f"Failed to load KEV JSON from {path}: {e}")
            return False

    async def _ensure_loaded(self):
        """Lazy-load data files into memory."""
        if self._loaded:
            return

        # Load EPSS scores, falling back to bundled fixture data
        epss_path = Path(self.epss_csv_path)
        fallback_epss_path = self._fixtures_dir / "epss_fallback.csv"
        epss_loaded = epss_path.exists() and self._load_epss_file(epss_path)
        if not epss_loaded:
            if not epss_path.exists():
                logger.warning(f"EPSS CSV not found at {self.epss_csv_path}")
            elif not self._epss_cache:
                logger.warning(f"EPSS CSV at {self.epss_csv_path} could not be parsed, using fallback")
            if self._load_epss_file(fallback_epss_path):
                self._epss_source = "epss_fallback"

        # Load CISA KEV catalog, falling back to bundled fixture data
        kev_path = Path(self.kev_json_path)
        fallback_kev_path = self._fixtures_dir / "kev_fallback.json"
        kev_loaded = kev_path.exists() and self._load_kev_file(kev_path)
        if not kev_loaded:
            if not kev_path.exists():
                logger.warning(f"KEV JSON not found at {self.kev_json_path}")
            elif not self._kev_cache:
                logger.warning(f"KEV JSON at {self.kev_json_path} could not be parsed, using fallback")
            if self._load_kev_file(fallback_kev_path):
                self._kev_source = "kev_fallback"

        self._loaded = True

    async def enrich(self, cve_id: str) -> ThreatIntelResult:
        await self._ensure_loaded()

        epss = self._epss_cache.get(cve_id, {"score": 0.0, "percentile": 0.0})
        in_kev = cve_id in self._kev_cache
        kev_data = self._kev_data.get(cve_id, {})

        sources = []
        if self._epss_cache:
            sources.append(self._epss_source)
        if self._kev_cache:
            sources.append(self._kev_source)

        return ThreatIntelResult(
            cve_id=cve_id,
            epss_score=epss["score"],
            epss_percentile=epss["percentile"],
            in_kev=in_kev,
            kev_date_added=kev_data.get("date_added"),
            kev_due_date=kev_data.get("due_date"),
            kev_ransomware_use=kev_data.get("ransomware_use", "Unknown"),
            # Dark web data not available in local mode (would need OTX dump)
            dark_web_mentions=0,
            exploit_available=in_kev,  # KEV implies exploit exists
            exploit_for_sale=False,
            ransomware_associated=kev_data.get("ransomware_use") == "Known",
            active_scanning=False,
            sources=sources,
        )

    async def get_epss(self, cve_id: str) -> float:
        await self._ensure_loaded()
        return self._epss_cache.get(cve_id, {"score": 0.0})["score"]

    async def is_in_kev(self, cve_id: str) -> bool:
        await self._ensure_loaded()
        return cve_id in self._kev_cache

    async def get_dark_web_intel(self, cve_id: str) -> dict:
        """Limited in local mode - only KEV-derived exploit data."""
        await self._ensure_loaded()
        in_kev = cve_id in self._kev_cache
        return {
            "dark_web_mentions": 0,
            "exploit_available": in_kev,
            "exploit_for_sale": False,
            "ransomware_associated": self._kev_data.get(cve_id, {}).get(
                "ransomware_use"
            ) == "Known",
            "active_scanning": False,
            "note": "Limited data in local mode. Use THREATINTEL_MODE=api for full dark web coverage.",
        }

    async def refresh_cache(self) -> bool:
        """In local mode, re-read the files from disk."""
        self._loaded = False
        self._epss_cache.clear()
        self._kev_cache.clear()
        self._kev_data.clear()
        await self._ensure_loaded()
        return True

    async def health_check(self) -> bool:
        return any([
            os.path.exists(self.epss_csv_path),
            os.path.exists(self.kev_json_path),
            (self._fixtures_dir / "epss_fallback.csv").exists(),
            (self._fixtures_dir / "kev_fallback.json").exists(),
        ])

    @property
    def provider_name(self) -> str:
        return "local"
