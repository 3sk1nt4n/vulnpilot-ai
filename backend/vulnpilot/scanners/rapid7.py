"""
VulnPilot AI - Rapid7 InsightVM Scanner Provider (FIXED)
Cloud Integrations API v4 with cursor-based pagination.
Fixes: correct endpoint paths, cursor pagination (no dup/gap),
9-region support, RateLimit-* header respect, circuit breaker.
"""

import logging
import os
from datetime import datetime
from typing import Optional

import httpx

from vulnpilot.scanners.base import ScannerProvider, NormalizedVuln
from vulnpilot.scanners.resilience import get_rate_limiter, get_circuit_breaker

logger = logging.getLogger(__name__)


class Rapid7Provider(ScannerProvider):
    """Rapid7 InsightVM Cloud Integrations API v4."""

    REGIONS = {"us","us2","us3","eu","ca","au","ap","me-central-1","ap-south-2"}

    def __init__(self):
        self.api_key = os.getenv("RAPID7_API_KEY", "")
        self.region = os.getenv("RAPID7_REGION", "us")
        if self.region not in self.REGIONS:
            logger.warning(f"Rapid7 region '{self.region}' invalid. Using 'us'")
            self.region = "us"
        self.base_url = f"https://{self.region}.api.insight.rapid7.com"
        self.timeout = 120.0
        self._rl = get_rate_limiter("rapid7")
        self._cb = get_circuit_breaker("rapid7")

    def _hdrs(self):
        return {"X-Api-Key": self.api_key, "Content-Type": "application/json", "Accept": "application/json"}

    async def connect(self) -> bool:
        if not self._cb.is_available():
            return False
        try:
            await self._rl.acquire()
            async with httpx.AsyncClient(timeout=30.0) as c:
                r = await c.get(f"{self.base_url}/validate", headers=self._hdrs())
                if r.status_code == 200:
                    self._cb.record_success()
                    logger.info(f"Rapid7 connected ({self.region})")
                    return True
                if r.status_code in (401, 403):
                    logger.error(f"Rapid7 auth failed: HTTP {r.status_code}")
                    return False
                self._cb.record_failure()
                return False
        except Exception as e:
            logger.error(f"Rapid7 connect failed: {e}")
            self._cb.record_failure()
            return False

    async def fetch_vulnerabilities(self, since: Optional[datetime] = None) -> list[NormalizedVuln]:
        if not self._cb.is_available():
            return []
        results = []
        cursor = None
        page = 0

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                while True:
                    page += 1
                    await self._rl.acquire()
                    body = {"asset": True, "vulnerability": True, "size": 500}
                    if cursor: body["cursor"] = cursor
                    if since:
                        body["filters"] = [{"type":"last-assessed","operator":"is-after",
                            "value": since.strftime("%Y-%m-%dT%H:%M:%S.000Z")}]

                    r = await c.post(f"{self.base_url}/vm/v4/integration/assets",
                        headers=self._hdrs(), json=body)

                    if r.status_code == 429:
                        reset = int(r.headers.get("RateLimit-Reset", "60"))
                        logger.warning(f"Rapid7 429. Waiting {reset}s")
                        import asyncio; await asyncio.sleep(reset + 1); continue
                    r.raise_for_status()
                    data = r.json()

                    for asset in data.get("resources", []):
                        hn = asset.get("host_name", "")
                        ips = asset.get("ip_addresses", [])
                        ip = ips[0] if isinstance(ips, list) and ips else ""
                        os_n = asset.get("os_name", "")
                        for v in asset.get("vulnerabilities", []):
                            n = self._norm(v, hn, ip, os_n)
                            if n: results.append(n)

                    meta = data.get("metadata", {})
                    new_cursor = meta.get("cursor")
                    if not new_cursor or new_cursor == cursor or page >= min(meta.get("total_pages",200), 200):
                        break
                    cursor = new_cursor

            logger.info(f"Rapid7: {len(results)} vulns fetched ({page} pages)")
            self._cb.record_success()
        except Exception as e:
            logger.error(f"Rapid7 fetch failed: {e}")
            self._cb.record_failure()
        return results

    def _norm(self, v, hn, ip, os_n) -> Optional[NormalizedVuln]:
        try:
            cves = v.get("cves", [])
            cve = cves[0] if isinstance(cves, list) and cves else ""
            if not cve: return None
            return NormalizedVuln(
                cve_id=cve, source_scanner="rapid7", source_id=str(v.get("id","")),
                cvss_base_score=float(v.get("cvss_v3_score") or v.get("cvss_v2_score") or 0),
                cvss_vector=v.get("cvss_v3_vector",""),
                cvss_version="3.1" if v.get("cvss_v3_score") else "2.0",
                title=str(v.get("title","Unknown"))[:500],
                description=str(v.get("description",""))[:2000],
                solution=str(v.get("solution",""))[:2000],
                hostname=hn, ip_address=ip, port=int(v.get("port",0)),
                protocol=str(v.get("protocol","")), os=os_n, raw_data=v)
        except Exception as e:
            logger.warning(f"Rapid7 normalize failed: {e}")
            return None

    async def health_check(self) -> bool:
        return await self.connect()

    @property
    def provider_name(self) -> str:
        return "rapid7"
