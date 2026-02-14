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
from datetime import datetime
from typing import Optional

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

    async def _ensure_loaded(self):
        """Lazy-load data files into memory."""
        if self._loaded:
            return

        # Load EPSS scores
        if os.path.exists(self.epss_csv_path):
            try:
                with open(self.epss_csv_path, "r") as f:
                    # Skip comment lines (EPSS CSV has header comments)
                    reader = csv.DictReader(
                        line for line in f if not line.startswith("#")
                    )
                    for row in reader:
                        cve = row.get("cve", "").strip()
                        if cve:
                            self._epss_cache[cve] = {
                                "score": float(row.get("epss", 0)),
                                "percentile": float(row.get("percentile", 0)) * 100,
                            }
                logger.info(f"Loaded {len(self._epss_cache)} EPSS scores from {self.epss_csv_path}")
            except Exception as e:
                logger.warning(f"Failed to load EPSS CSV: {e}")
        else:
            logger.warning(f"EPSS CSV not found at {self.epss_csv_path}")

        # Load CISA KEV catalog
        if os.path.exists(self.kev_json_path):
            try:
                with open(self.kev_json_path, "r") as f:
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
                logger.info(f"Loaded {len(self._kev_cache)} KEV entries from {self.kev_json_path}")
            except Exception as e:
                logger.warning(f"Failed to load KEV JSON: {e}")
        else:
            logger.warning(f"KEV JSON not found at {self.kev_json_path}")

        self._loaded = True

    async def enrich(self, cve_id: str) -> ThreatIntelResult:
        await self._ensure_loaded()

        epss = self._epss_cache.get(cve_id, {"score": 0.0, "percentile": 0.0})
        in_kev = cve_id in self._kev_cache
        kev_data = self._kev_data.get(cve_id, {})

        sources = []
        if self._epss_cache:
            sources.append("epss_csv")
        if self._kev_cache:
            sources.append("kev_json")

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
        return os.path.exists(self.epss_csv_path) or os.path.exists(self.kev_json_path)

    @property
    def provider_name(self) -> str:
        return "local"
