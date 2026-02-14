"""
VulnPilot AI - Qualys VMDR Scanner Provider (FIXED)
Proper QID→CVE mapping via KnowledgeBase API.
Previous version regex'd RESULTS field - missed ~40% of CVEs.
Now: 1) fetch detections, 2) batch KB lookup for CVE resolution.
"""

import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional

import httpx

from vulnpilot.scanners.base import ScannerProvider, NormalizedVuln
from vulnpilot.scanners.resilience import get_rate_limiter, get_circuit_breaker

logger = logging.getLogger(__name__)


class QualysProvider(ScannerProvider):
    """Qualys VMDR - two-step: detections (QIDs) → KB lookup (CVEs)."""

    def __init__(self):
        self.api_url = os.getenv("QUALYS_API_URL", "https://qualysapi.qualys.com")
        self.username = os.getenv("QUALYS_USERNAME", "")
        self.password = os.getenv("QUALYS_PASSWORD", "")
        self.timeout = 120.0
        self._rl = get_rate_limiter("qualys")
        self._cb = get_circuit_breaker("qualys")
        self._qid_cve: dict[str, list[str]] = {}  # QID → [CVE-xxx, ...]

    def _hdrs(self):
        return {"X-Requested-With": "VulnPilot AI"}

    async def connect(self) -> bool:
        if not self._cb.is_available():
            return False
        try:
            await self._rl.acquire()
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.get(f"{self.api_url}/api/2.0/fo/activity_log/",
                    auth=(self.username, self.password), headers=self._hdrs(),
                    params={"action": "list", "truncation_limit": 1})
                ok = r.status_code == 200
                (self._cb.record_success if ok else self._cb.record_failure)()
                return ok
        except Exception as e:
            logger.error(f"Qualys connect failed: {e}")
            self._cb.record_failure()
            return False

    async def fetch_vulnerabilities(self, since: Optional[datetime] = None) -> list[NormalizedVuln]:
        if not self._cb.is_available():
            return []
        try:
            # Step 1: Fetch detections with pagination
            dets = await self._fetch_all_detections(since)
            qids = list({d["qid"] for d in dets})
            logger.info(f"Qualys: {len(dets)} detections, {len(qids)} unique QIDs")

            # Step 2: Batch KB lookup for QID → CVE
            if qids:
                await self._batch_kb_lookup(qids)

            # Step 3: Normalize
            results = []
            for d in dets:
                cves = self._qid_cve.get(d["qid"], [])
                if not cves and d.get("results"):
                    cves = re.findall(r"CVE-\d{4}-\d{4,}", d["results"])
                for cve in cves:
                    results.append(NormalizedVuln(
                        cve_id=cve, source_scanner="qualys", source_id=d["qid"],
                        cvss_base_score=d.get("cvss", 0.0),
                        title=d.get("title", f"QID {d['qid']}")[:200],
                        description=d.get("results", "")[:2000],
                        hostname=d.get("hostname", ""), ip_address=d.get("ip", ""),
                        port=d.get("port", 0), protocol=d.get("protocol", ""),
                        os=d.get("os", ""),
                        raw_data={"qid": d["qid"], "severity": d.get("severity", "")},
                    ))
            logger.info(f"Qualys: {len(results)} CVE findings from {len(dets)} detections")
            self._cb.record_success()
            return results
        except Exception as e:
            logger.error(f"Qualys fetch failed: {e}")
            self._cb.record_failure()
            return []

    async def _fetch_all_detections(self, since=None):
        all_d = []
        params = {"action": "list", "show_results": 1, "show_igs": 0,
                  "status": "New,Active,Re-Opened,Fixed", "severities": "3,4,5"}
        if since:
            params["detection_updated_since"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        sev_map = {"1": 2.0, "2": 4.0, "3": 6.5, "4": 8.5, "5": 10.0}

        async with httpx.AsyncClient(timeout=self.timeout) as c:
            page = 0
            while page < 100:
                page += 1
                await self._rl.acquire()
                try:
                    r = await c.get(f"{self.api_url}/api/2.0/fo/asset/host/vm/detection/",
                        auth=(self.username, self.password), headers=self._hdrs(), params=params)
                    if r.status_code == 409:
                        wait = int(r.headers.get("X-RateLimit-ToWait-Sec", "30"))
                        logger.warning(f"Qualys 409 rate limited. Waiting {wait}s")
                        import asyncio; await asyncio.sleep(wait); continue
                    r.raise_for_status()
                except Exception as e:
                    logger.error(f"Qualys page {page} failed: {e}"); break

                root = ET.fromstring(r.text)
                next_id = None
                warn = root.find(".//WARNING")
                if warn is not None:
                    url_e = warn.find("URL")
                    if url_e is not None and url_e.text:
                        m = re.search(r"id_min=(\d+)", url_e.text)
                        if m: next_id = m.group(1)

                for host in root.findall(".//HOST"):
                    hn, ip, os_n = host.findtext("DNS",""), host.findtext("IP",""), host.findtext("OS","")
                    for det in host.findall(".//DETECTION"):
                        sev = det.findtext("SEVERITY", "1")
                        all_d.append({"qid": det.findtext("QID",""), "severity": sev,
                            "results": det.findtext("RESULTS",""),
                            "port": int(det.findtext("PORT","0")),
                            "protocol": det.findtext("PROTOCOL",""),
                            "hostname": hn, "ip": ip, "os": os_n,
                            "title": det.findtext("RESULTS","")[:200],
                            "cvss": sev_map.get(sev, 5.0)})

                if not next_id: break
                params["id_min"] = next_id
        return all_d

    async def _batch_kb_lookup(self, qids):
        uncached = [q for q in qids if q not in self._qid_cve]
        if not uncached: return
        batches = [uncached[i:i+50] for i in range(0, len(uncached), 50)]
        logger.info(f"Qualys KB: {len(uncached)} QIDs in {len(batches)} batches")
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            for i, batch in enumerate(batches):
                try:
                    await self._rl.acquire()
                    r = await c.get(f"{self.api_url}/api/2.0/fo/knowledge_base/vuln/",
                        auth=(self.username, self.password), headers=self._hdrs(),
                        params={"action": "list", "ids": ",".join(batch), "details": "All"})
                    if r.status_code == 409:
                        import asyncio
                        await asyncio.sleep(int(r.headers.get("X-RateLimit-ToWait-Sec","30"))); continue
                    r.raise_for_status()
                    root = ET.fromstring(r.text)
                    for vuln in root.findall(".//VULN"):
                        qid = vuln.findtext("QID","")
                        if not qid: continue
                        cves = [e.text.strip() for e in vuln.findall(".//CVE_LIST/CVE/ID")
                                if e.text and e.text.strip().startswith("CVE-")]
                        if cves: self._qid_cve[qid] = cves
                    logger.info(f"KB batch {i+1}/{len(batches)}: {sum(1 for q in batch if q in self._qid_cve)}/{len(batch)}")
                except Exception as e:
                    logger.error(f"KB batch {i+1} failed: {e}")

    async def health_check(self) -> bool:
        return await self.connect()

    @property
    def provider_name(self) -> str:
        return "qualys"
