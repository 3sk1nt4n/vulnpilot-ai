"""
VulnPilot AI - Tenable.io Scanner Provider (UPGRADED)
Now with: circuit breaker, EPSS/VPRv2/CVSS4 field extraction,
multi-CVE expansion per plugin, rate limit awareness.
"""
import logging, os
from datetime import datetime
from typing import Optional
from vulnpilot.scanners.base import ScannerProvider, NormalizedVuln
from vulnpilot.scanners.resilience import get_circuit_breaker

logger = logging.getLogger(__name__)

class TenableProvider(ScannerProvider):
    def __init__(self):
        self.access_key = os.getenv("TENABLE_ACCESS_KEY", "")
        self.secret_key = os.getenv("TENABLE_SECRET_KEY", "")
        self._client = None
        self._cb = get_circuit_breaker("tenable")

    def _get_client(self):
        if self._client is None:
            try:
                from tenable.io import TenableIO
                self._client = TenableIO(access_key=self.access_key, secret_key=self.secret_key)
            except ImportError:
                raise RuntimeError("pytenable not installed. Run: pip install pytenable>=1.9.0")
        return self._client

    async def connect(self) -> bool:
        if not self._cb.is_available():
            logger.warning("Tenable circuit breaker OPEN"); return False
        try:
            tio = self._get_client(); tio.server.status()
            logger.info("Connected to Tenable.io"); self._cb.record_success(); return True
        except Exception as e:
            logger.error(f"Tenable connection failed: {e}"); self._cb.record_failure(); return False

    async def fetch_vulnerabilities(self, since: Optional[datetime] = None) -> list[NormalizedVuln]:
        if not self._cb.is_available(): return []
        tio = self._get_client(); results = []
        try:
            kw = {"severity": ["critical", "high", "medium"]}
            if since: kw["since"] = int(since.timestamp())
            logger.info("Starting Tenable.io vulnerability export...")
            for vuln in tio.exports.vulns(**kw):
                normed = self._normalize(vuln)
                results.extend(normed)  # Can return multiple (multi-CVE plugins)
            logger.info(f"Tenable: {len(results)} CVE findings"); self._cb.record_success()
        except Exception as e:
            logger.error(f"Tenable export failed: {e}"); self._cb.record_failure()
            try:  # Fallback
                logger.info("Trying workbench fallback...")
                for v in tio.workbenches.vuln_outputs():
                    n = self._normalize_wb(v)
                    if n: results.append(n)
                logger.info(f"Workbench fallback: {len(results)} vulns")
            except Exception as e2:
                logger.error(f"Workbench also failed: {e2}")
        return results

    def _normalize(self, raw: dict) -> list[NormalizedVuln]:
        """Normalize export record. Expands multi-CVE plugins into separate findings."""
        try:
            plugin = raw.get("plugin", {}); asset = raw.get("asset", {})
            cves = plugin.get("cve", [])
            if not cves: return []
            if isinstance(cves, str): cves = [cves]

            sev_map = {0: 0.0, 1: 3.0, 2: 5.0, 3: 7.5, 4: 9.5}
            cvss = float(plugin.get("cvss3_base_score") or plugin.get("cvss_base_score")
                         or sev_map.get(raw.get("severity", 0), 0))
            # New 2025 fields
            epss = plugin.get("epss_score")
            vpr_v2 = plugin.get("vpr_v2", {}).get("score") if isinstance(plugin.get("vpr_v2"), dict) else plugin.get("vpr_v2")
            cvss4 = plugin.get("cvss4_base_score")

            results = []
            for cve_id in cves:
                if not cve_id.startswith("CVE-"): continue
                results.append(NormalizedVuln(
                    cve_id=cve_id, source_scanner="tenable",
                    source_id=str(plugin.get("id", "")),
                    cvss_base_score=float(cvss4 or cvss),
                    cvss_vector=plugin.get("cvss3_vector", plugin.get("cvss_vector", "")),
                    cvss_version="4.0" if cvss4 else ("3.1" if plugin.get("cvss3_base_score") else "2.0"),
                    title=plugin.get("name", "Unknown")[:500],
                    description=plugin.get("description", "")[:2000],
                    solution=plugin.get("solution", "")[:2000],
                    cwe_id=str((plugin.get("cwe") or [None])[0] or ""),
                    published_date=self._parse_date(plugin.get("publication_date")),
                    last_modified=self._parse_date(plugin.get("modification_date")),
                    hostname=asset.get("hostname", ""),
                    ip_address=asset.get("ipv4", asset.get("ipv6", "")),
                    port=int(raw.get("port", {}).get("port", 0)),
                    protocol=raw.get("port", {}).get("protocol", ""),
                    os=(asset.get("operating_system") or [""])[0] if asset.get("operating_system") else "",
                    raw_data={"epss_score": epss, "vpr_v2": vpr_v2, "cvss4": cvss4,
                              "plugin_id": plugin.get("id"), "state": raw.get("state")},
                ))
            return results
        except Exception as e:
            logger.warning(f"Tenable normalize failed: {e}"); return []

    def _normalize_wb(self, raw: dict) -> Optional[NormalizedVuln]:
        try:
            cves = raw.get("cve", [])
            cve_id = (cves[0] if isinstance(cves, list) else cves) if cves else ""
            if not cve_id: return None
            return NormalizedVuln(
                cve_id=cve_id, source_scanner="tenable",
                source_id=str(raw.get("plugin_id", "")),
                cvss_base_score=float(raw.get("cvss3_base_score", raw.get("cvss_base_score", 0))),
                title=raw.get("plugin_name", "")[:500],
                description=raw.get("description", "")[:2000],
                solution=raw.get("solution", "")[:2000],
                hostname=raw.get("hostname", ""), ip_address=raw.get("host_ip", ""),
                port=int(raw.get("port", 0)), protocol=raw.get("protocol", ""), raw_data=raw,
            )
        except Exception as e:
            logger.warning(f"Tenable WB normalize failed: {e}"); return None

    def _parse_date(self, s: Optional[str]) -> Optional[datetime]:
        if not s: return None
        try: return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except: return None

    async def health_check(self) -> bool:
        try: self._get_client().server.status(); return True
        except: return False

    @property
    def provider_name(self) -> str: return "tenable"
