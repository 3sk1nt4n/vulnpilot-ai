"""
VulnPilot AI - API Threat Intelligence Provider (UPGRADED)
Live API calls to EPSS, CISA KEV, AlienVault OTX, GreyNoise, abuse.ch.

FIXES:
- KEV catalog: Downloaded ONCE and cached (was re-downloading per CVE)
- Rate limiting: Respects API limits across all providers
- Concurrent enrichment: asyncio.gather for parallel API calls per CVE
- Batch EPSS: Query up to 30 CVEs in one API call
- abuse.ch: Auth-Key header (required since June 2025)
"""
import asyncio, logging, os
from datetime import datetime, timedelta
from typing import Optional
import httpx
from vulnpilot.threatintel.base import ThreatIntelProvider, ThreatIntelResult
from vulnpilot.scanners.resilience import RateLimiter

logger = logging.getLogger(__name__)

class APIThreatIntelProvider(ThreatIntelProvider):
    def __init__(self):
        self.otx_api_key = os.getenv("OTX_API_KEY", "")
        self.greynoise_api_key = os.getenv("GREYNOISE_API_KEY", "")
        self.abusech_key = os.getenv("ABUSECH_AUTH_KEY", "")
        self.timeout = 15.0
        self._cache: dict[str, ThreatIntelResult] = {}
        # KEV catalog: download once, cache for 1 hour
        self._kev_catalog: dict[str, dict] = {}
        self._kev_loaded_at: Optional[datetime] = None
        # Rate limiters
        self._rl_epss = RateLimiter(max_requests=15, window_seconds=60)
        self._rl_otx = RateLimiter(max_requests=50, window_seconds=60)
        self._rl_greynoise = RateLimiter(max_requests=45, window_seconds=86400)  # 50/day free
        self._rl_abusech = RateLimiter(max_requests=8, window_seconds=60)
        # Dark web provider
        self._darkweb = None
        try:
            from vulnpilot.threatintel.darkweb_provider import DarkWebIntelProvider
            self._darkweb = DarkWebIntelProvider()
        except Exception: pass

    async def enrich(self, cve_id: str) -> ThreatIntelResult:
        if cve_id in self._cache:
            return self._cache[cve_id]

        # Run all intel sources in PARALLEL (not sequential)
        epss_task = self.get_epss(cve_id)
        kev_task = self._check_kev(cve_id)
        darkweb_task = self.get_dark_web_intel(cve_id)
        dw_enrich_task = self._darkweb.enrich(cve_id) if self._darkweb else asyncio.coroutine(lambda: None)()

        epss, kev_data, dark_web = await asyncio.gather(
            epss_task, kev_task, darkweb_task, return_exceptions=True
        )
        # Handle exceptions from gather
        if isinstance(epss, Exception): epss = 0.0
        if isinstance(kev_data, Exception): kev_data = {"in_kev": False}
        if isinstance(dark_web, Exception): dark_web = {}

        dw_intel = None
        if self._darkweb:
            try: dw_intel = await self._darkweb.enrich(cve_id)
            except: pass

        sources = ["epss_api", "kev_api"]
        if self.otx_api_key: sources.append("otx_api")
        if self.greynoise_api_key: sources.append("greynoise_api")

        dw_mentions = dark_web.get("mentions", 0) if isinstance(dark_web, dict) else 0
        exploit_available = dark_web.get("exploit_available", False) if isinstance(dark_web, dict) else False
        exploit_for_sale = dark_web.get("exploit_for_sale", False) if isinstance(dark_web, dict) else False
        active_scanning = dark_web.get("active_scanning", False) if isinstance(dark_web, dict) else False
        ransomware = kev_data.get("ransomware_use") == "Known" if isinstance(kev_data, dict) else False

        if dw_intel and hasattr(dw_intel, 'dark_web_mentions'):
            dw_mentions += dw_intel.dark_web_mentions
            exploit_available = exploit_available or getattr(dw_intel, 'poc_available', False) or getattr(dw_intel, 'weaponized', False)
            exploit_for_sale = exploit_for_sale or getattr(dw_intel, 'exploit_for_sale', False)
            active_scanning = active_scanning or getattr(dw_intel, 'active_scanning', False)
            ransomware = ransomware or getattr(dw_intel, 'ransomware_associated', False)
            sources.extend(getattr(dw_intel, 'sources', []))

        result = ThreatIntelResult(
            cve_id=cve_id, epss_score=epss if isinstance(epss, (int, float)) else 0.0,
            epss_percentile=0.0,
            in_kev=kev_data.get("in_kev", False) if isinstance(kev_data, dict) else False,
            kev_date_added=kev_data.get("date_added") if isinstance(kev_data, dict) else None,
            kev_due_date=kev_data.get("due_date") if isinstance(kev_data, dict) else None,
            kev_ransomware_use=kev_data.get("ransomware_use", "Unknown") if isinstance(kev_data, dict) else "Unknown",
            dark_web_mentions=dw_mentions, exploit_available=exploit_available,
            exploit_for_sale=exploit_for_sale, ransomware_associated=ransomware,
            active_scanning=active_scanning, sources=sources,
        )
        self._cache[cve_id] = result
        return result

    async def enrich_batch(self, cve_ids: list[str]) -> list[ThreatIntelResult]:
        """Batch enrichment - uses batch EPSS API, then parallel per-CVE for other sources."""
        # Batch EPSS (up to 30 per call)
        await self._batch_epss(cve_ids)
        # Parallel enrichment (with concurrency limit)
        sem = asyncio.Semaphore(5)  # Max 5 concurrent CVE enrichments
        async def _enrich_one(cve_id):
            async with sem:
                return await self.enrich(cve_id)
        results = await asyncio.gather(*[_enrich_one(c) for c in cve_ids], return_exceptions=True)
        return [r for r in results if isinstance(r, ThreatIntelResult)]

    async def _batch_epss(self, cve_ids: list[str]) -> None:
        """Pre-fetch EPSS scores in batch (up to 30 per API call)."""
        uncached = [c for c in cve_ids if c not in self._cache]
        if not uncached: return
        for i in range(0, len(uncached), 30):
            batch = uncached[i:i+30]
            await self._rl_epss.acquire()
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get("https://api.first.org/data/v1/epss",
                                           params={"cve": ",".join(batch)})
                    resp.raise_for_status()
                    for item in resp.json().get("data", []):
                        cve = item.get("cve", "")
                        if cve:
                            # Pre-populate cache with EPSS data
                            self._cache.setdefault(cve, ThreatIntelResult(cve_id=cve))
                            # Store EPSS in a temp dict for enrich() to pick up
                            if not hasattr(self, '_epss_cache'): self._epss_cache = {}
                            self._epss_cache[cve] = float(item.get("epss", 0))
            except Exception as e:
                logger.warning(f"Batch EPSS failed: {e}")

    async def get_epss(self, cve_id: str) -> float:
        # Check batch cache first
        if hasattr(self, '_epss_cache') and cve_id in self._epss_cache:
            return self._epss_cache[cve_id]
        await self._rl_epss.acquire()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get("https://api.first.org/data/v1/epss", params={"cve": cve_id})
                resp.raise_for_status()
                data = resp.json().get("data", [])
                return float(data[0].get("epss", 0)) if data else 0.0
        except Exception as e:
            logger.warning(f"EPSS failed for {cve_id}: {e}"); return 0.0

    async def _load_kev_catalog(self) -> None:
        """Download KEV catalog ONCE, cache for 1 hour."""
        if self._kev_loaded_at and (datetime.utcnow() - self._kev_loaded_at) < timedelta(hours=1):
            return
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
                resp.raise_for_status()
                catalog = resp.json()
                self._kev_catalog = {
                    v["cveID"]: {
                        "in_kev": True,
                        "date_added": v.get("dateAdded"),
                        "due_date": v.get("dueDate"),
                        "ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                    }
                    for v in catalog.get("vulnerabilities", [])
                }
                self._kev_loaded_at = datetime.utcnow()
                logger.info(f"KEV catalog loaded: {len(self._kev_catalog)} entries")
        except Exception as e:
            logger.warning(f"KEV catalog download failed: {e}")

    async def is_in_kev(self, cve_id: str) -> bool:
        data = await self._check_kev(cve_id)
        return data.get("in_kev", False)

    async def _check_kev(self, cve_id: str) -> dict:
        await self._load_kev_catalog()
        return self._kev_catalog.get(cve_id, {"in_kev": False})

    async def get_dark_web_intel(self, cve_id: str) -> dict:
        result = {"mentions": 0, "exploit_available": False, "exploit_for_sale": False, "active_scanning": False}
        tasks = []
        if self.otx_api_key: tasks.append(self._query_otx(cve_id))
        if self.greynoise_api_key: tasks.append(self._query_greynoise(cve_id))
        if self.abusech_key: tasks.append(self._query_abusech(cve_id))
        if not tasks: return result

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for resp in responses:
            if isinstance(resp, Exception): continue
            if isinstance(resp, dict):
                result["mentions"] += resp.get("mentions", 0)
                result["exploit_available"] = result["exploit_available"] or resp.get("exploit_available", False)
                result["active_scanning"] = result["active_scanning"] or resp.get("active_scanning", False)
        return result

    async def _query_otx(self, cve_id: str) -> dict:
        await self._rl_otx.acquire()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.get(f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general",
                               headers={"X-OTX-API-KEY": self.otx_api_key})
                if r.status_code == 200:
                    pc = r.json().get("pulse_info", {}).get("count", 0)
                    return {"mentions": pc, "exploit_available": pc > 0}
        except Exception as e: logger.debug(f"OTX failed for {cve_id}: {e}")
        return {}

    async def _query_greynoise(self, cve_id: str) -> dict:
        await self._rl_greynoise.acquire()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.get(f"https://api.greynoise.io/v3/cve/{cve_id}",
                               headers={"key": self.greynoise_api_key, "Accept": "application/json"})
                if r.status_code == 200:
                    d = r.json()
                    return {"active_scanning": (d.get("benign_count",0)+d.get("malicious_count",0))>0,
                            "mentions": d.get("malicious_count", 0)}
        except Exception as e: logger.debug(f"GreyNoise failed for {cve_id}: {e}")
        return {}

    async def _query_abusech(self, cve_id: str) -> dict:
        await self._rl_abusech.acquire()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post("https://threatfox-api.abuse.ch/api/v1/",
                                json={"query": "search_term", "search_term": cve_id},
                                headers={"Auth-Key": self.abusech_key})
                if r.status_code == 200:
                    d = r.json()
                    if d.get("query_status") == "ok" and d.get("data"):
                        return {"mentions": len(d["data"]), "exploit_available": True}
        except Exception as e: logger.debug(f"abuse.ch failed for {cve_id}: {e}")
        return {}

    async def refresh_cache(self) -> bool:
        self._cache.clear(); self._kev_catalog.clear(); self._kev_loaded_at = None
        if hasattr(self, '_epss_cache'): self._epss_cache.clear()
        logger.info("API threat intel cache cleared"); return True

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get("https://api.first.org/data/v1/epss?cve=CVE-2024-0001")
                return r.status_code == 200
        except: return False

    @property
    def provider_name(self) -> str: return "api"
