"""
VulnPilot AI - Wazuh Scanner Provider (UPGRADED)
Continuous real-time vulnerability detection via agent-based monitoring.

KEY FIXES:
- Primary: Query Wazuh INDEXER (OpenSearch, port 9200) for vuln data
- Fallback: Legacy /vulnerability/{agent_id} for Wazuh < 4.8
- Rate limiting (300 req/min)
- Token refresh handling (15min expiry)
- Circuit breaker

Since Wazuh 4.8+, vulnerability data lives in the Wazuh indexer
(OpenSearch) at index wazuh-states-vulnerabilities-*, NOT the REST API.
"""
import asyncio, logging, os
from datetime import datetime, timedelta
from typing import Optional
import httpx
from vulnpilot.scanners.base import ScannerProvider, NormalizedVuln
from vulnpilot.scanners.resilience import get_rate_limiter, get_circuit_breaker

logger = logging.getLogger(__name__)

class WazuhProvider(ScannerProvider):
    def __init__(self):
        self.api_url = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
        self.indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
        self.indexer_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        self.indexer_pass = os.getenv("WAZUH_INDEXER_PASS", os.getenv("WAZUH_INDEXER_PASSWORD", "admin"))
        self.username = os.getenv("WAZUH_USERNAME", "wazuh-wui")
        self.password = os.getenv("WAZUH_PASSWORD", "")
        self.verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"
        self.timeout = 30.0
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._rl = get_rate_limiter("wazuh")
        self._cb = get_circuit_breaker("wazuh")

    async def _get_token(self) -> str:
        if self._token and self._token_expiry and datetime.utcnow() < self._token_expiry:
            return self._token
        await self._rl.acquire()
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as c:
            r = await c.post(f"{self.api_url}/security/user/authenticate", auth=(self.username, self.password))
            r.raise_for_status()
            self._token = r.json().get("data", {}).get("token", "")
            self._token_expiry = datetime.utcnow() + timedelta(seconds=800)
            return self._token

    async def _api_get(self, endpoint: str, params: dict = None) -> dict:
        await self._rl.acquire()
        token = await self._get_token()
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as c:
            r = await c.get(f"{self.api_url}{endpoint}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
            if r.status_code == 401:
                self._token = None; token = await self._get_token()
                r = await c.get(f"{self.api_url}{endpoint}", headers={"Authorization": f"Bearer {token}"}, params=params or {})
            r.raise_for_status(); return r.json()

    async def connect(self) -> bool:
        if not self._cb.is_available(): return False
        try:
            await self._get_token()
            self._cb.record_success(); return True
        except Exception as e:
            logger.error(f"Wazuh connection failed: {e}"); self._cb.record_failure(); return False

    async def fetch_vulnerabilities(self, since: Optional[datetime] = None, **kwargs) -> list[NormalizedVuln]:
        if not self._cb.is_available(): return []
        # Try indexer first (Wazuh 4.8+), then fallback to REST API
        try:
            results = await self._fetch_from_indexer(since)
            if results:
                logger.info(f"Wazuh indexer: {len(results)} CVE findings")
                self._cb.record_success(); return results
        except Exception as e:
            logger.info(f"Wazuh indexer not available ({e}), falling back to REST API")

        # Fallback: legacy REST API (Wazuh < 4.8)
        try:
            results = await self._fetch_from_api(since)
            logger.info(f"Wazuh REST API: {len(results)} CVE findings")
            self._cb.record_success(); return results
        except Exception as e:
            logger.error(f"Wazuh fetch failed: {e}"); self._cb.record_failure(); return []

    async def _fetch_from_indexer(self, since: Optional[datetime] = None) -> list[NormalizedVuln]:
        """Query Wazuh indexer (OpenSearch) for vulnerability states.
        This is the primary method for Wazuh 4.8+."""
        query = {"query": {"bool": {"must": [{"exists": {"field": "vulnerability.id"}}]}}, "size": 10000}
        if since:
            query["query"]["bool"]["must"].append({"range": {"@timestamp": {"gte": since.isoformat()}}})

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=60.0) as c:
            r = await c.post(
                f"{self.indexer_url}/wazuh-states-vulnerabilities-*/_search",
                auth=(self.indexer_user, self.indexer_pass),
                json=query, headers={"Content-Type": "application/json"},
            )
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])

        results = []
        for hit in hits:
            src = hit.get("_source", {})
            vuln = src.get("vulnerability", {})
            agent = src.get("agent", {})
            pkg = src.get("package", {})
            cve_id = vuln.get("id", "")
            if not cve_id or not cve_id.startswith("CVE-"): continue

            cvss = float(vuln.get("score", {}).get("base", 0) if isinstance(vuln.get("score"), dict) else vuln.get("score", 0))
            sev = (vuln.get("severity", "") or "").lower()
            if cvss == 0: cvss = {"critical":9.5,"high":7.5,"medium":5.0,"low":2.5}.get(sev, 0)

            results.append(NormalizedVuln(
                cve_id=cve_id, source_scanner="wazuh",
                source_id=f"wazuh-{agent.get('id','')}-{cve_id}",
                cvss_base_score=cvss,
                title=vuln.get("title", "") or vuln.get("description", "")[:200],
                description=vuln.get("description", "")[:2000],
                hostname=agent.get("name", ""), ip_address=agent.get("ip", ""),
                os=f"{agent.get('os',{}).get('name','')} {agent.get('os',{}).get('version','')}".strip(),
                software=f"{pkg.get('name','')} {pkg.get('version','')}".strip(),
                raw_data={"agent_id": agent.get("id"), "severity": sev,
                          "package": pkg, "source": "indexer"},
            ))
        return results

    async def _fetch_from_api(self, since: Optional[datetime] = None) -> list[NormalizedVuln]:
        """Fallback: Legacy REST API for Wazuh < 4.8."""
        agents_data = await self._api_get("/agents", params={"status": "active", "limit": 500, "select": "id,name,ip,os"})
        agents = agents_data.get("data", {}).get("affected_items", [])
        logger.info(f"Wazuh REST: {len(agents)} active agents")

        results = []
        for agent in agents:
            aid = agent.get("id", ""); aname = agent.get("name", ""); aip = agent.get("ip", "")
            aos = agent.get("os", {}); os_name = f"{aos.get('name','')} {aos.get('version','')}".strip()
            try:
                offset = 0
                while True:
                    await self._rl.acquire()
                    data = await self._api_get(f"/vulnerability/{aid}", params={"offset": offset, "limit": 500})
                    items = data.get("data", {}).get("affected_items", [])
                    if not items: break
                    for v in items:
                        cve_id = v.get("cve", "")
                        if not cve_id or not cve_id.startswith("CVE-"): continue
                        sev = (v.get("severity","") or "").lower()
                        cvss = float(v.get("cvss3_score") or v.get("cvss2_score") or {"critical":9.5,"high":7.5,"medium":5.0,"low":2.5}.get(sev, 0))
                        results.append(NormalizedVuln(
                            cve_id=cve_id, source_scanner="wazuh",
                            source_id=f"wazuh-{aid}-{cve_id}", cvss_base_score=cvss,
                            title=v.get("title","") or v.get("name",""),
                            description=v.get("rationale","")[:2000], solution=v.get("remediation","")[:2000],
                            hostname=aname, ip_address=aip, os=os_name,
                            software=v.get("package",{}).get("name",""),
                            raw_data={"agent_id": aid, "source": "rest_api"},
                        ))
                    total = data.get("data",{}).get("total_affected_items", 0)
                    offset += 500
                    if offset >= total: break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.debug(f"Agent {aid}: /vulnerability not available (pre-4.3 or vuln detector off)")
                else: logger.warning(f"Agent {aid} failed: {e}")
            except Exception as e:
                logger.warning(f"Agent {aid} failed: {e}")
        return results

    async def health_check(self) -> bool:
        try:
            await self._get_token()
            data = await self._api_get("/manager/info")
            ver = data.get("data",{}).get("affected_items",[{}])[0].get("version","?")
            logger.info(f"Wazuh: Connected to v{ver}"); return True
        except Exception as e:
            logger.error(f"Wazuh health check failed: {e}"); return False

    @property
    def provider_name(self) -> str: return "wazuh"
