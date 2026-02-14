"""
VulnPilot AI - OpenVAS/Greenbone Scanner Provider (REWRITTEN)
Uses GMP (Greenbone Management Protocol) via python-gvm.

CRITICAL FIX: Previous version used a REST API that DOES NOT EXIST.
OpenVAS/Greenbone communicates via GMP - XML over Unix socket or TLS.
There is no official REST API.

Requires: pip install python-gvm gvm-tools
"""
import logging, os, re
from datetime import datetime
from typing import Optional
from xml.etree import ElementTree as ET

from vulnpilot.scanners.base import ScannerProvider, NormalizedVuln
from vulnpilot.scanners.resilience import get_circuit_breaker

logger = logging.getLogger(__name__)

class OpenVASProvider(ScannerProvider):
    """OpenVAS/Greenbone via GMP protocol.

    Connection modes:
    1. Unix socket (default): /run/gvmd/gvmd.sock
    2. TLS: host:port (typically 9390)
    """
    def __init__(self):
        self.host = os.getenv("OPENVAS_HOST", "localhost")
        self.port = int(os.getenv("OPENVAS_PORT", "9390"))
        self.user = os.getenv("OPENVAS_USERNAME", os.getenv("OPENVAS_USER", "admin"))
        self.password = os.getenv("OPENVAS_PASSWORD", "admin")
        self.socket_path = os.getenv("OPENVAS_SOCKET", "")  # e.g. /run/gvmd/gvmd.sock
        self.timeout = int(os.getenv("OPENVAS_TIMEOUT", "300"))  # 5min default (large scans)
        self._cb = get_circuit_breaker("openvas")

    def _get_connection(self):
        """Create GMP connection - socket or TLS."""
        try:
            from gvm.connections import UnixSocketConnection, TLSConnection
        except ImportError:
            raise RuntimeError("python-gvm not installed. Run: pip install python-gvm gvm-tools")
        if self.socket_path:
            return UnixSocketConnection(path=self.socket_path, timeout=self.timeout)
        else:
            return TLSConnection(hostname=self.host, port=self.port, timeout=self.timeout)

    async def connect(self) -> bool:
        if not self._cb.is_available():
            logger.warning("OpenVAS circuit breaker OPEN"); return False
        try:
            from gvm.protocols.gmp import Gmp
            conn = self._get_connection()
            with Gmp(connection=conn) as gmp:
                gmp.authenticate(self.user, self.password)
                version = gmp.get_version()
                logger.info(f"Connected to OpenVAS/Greenbone (GMP)")
                self._cb.record_success(); return True
        except Exception as e:
            logger.error(f"OpenVAS connection failed: {e}")
            self._cb.record_failure(); return False

    async def fetch_vulnerabilities(self, since: Optional[datetime] = None) -> list[NormalizedVuln]:
        if not self._cb.is_available(): return []
        results = []
        try:
            from gvm.protocols.gmp import Gmp
            conn = self._get_connection()
            with Gmp(connection=conn) as gmp:
                gmp.authenticate(self.user, self.password)

                # Get latest report
                reports_xml = gmp.get_reports(
                    filter_string="status=Done sort-reverse=date rows=1"
                )
                root = ET.fromstring(reports_xml)
                report_elem = root.find(".//report")
                if report_elem is None:
                    logger.warning("No completed OpenVAS reports found"); return []

                report_id = report_elem.get("id", "")
                logger.info(f"Processing OpenVAS report: {report_id}")

                # Fetch results with severity > 0
                results_xml = gmp.get_results(
                    filter_string=f"report_id={report_id} min_qod=70 severity>0 rows=-1"
                )
                rroot = ET.fromstring(results_xml)

                for result in rroot.findall(".//result"):
                    normed = self._normalize_result(result)
                    if normed: results.append(normed)

            logger.info(f"OpenVAS: {len(results)} CVE findings")
            self._cb.record_success()
        except Exception as e:
            logger.error(f"OpenVAS fetch failed: {e}")
            self._cb.record_failure()
        return results

    def _normalize_result(self, result) -> Optional[NormalizedVuln]:
        try:
            nvt = result.find("nvt")
            if nvt is None: return None
            oid = nvt.get("oid", "")

            # Extract CVEs from refs
            cves = []
            refs = nvt.find("refs")
            if refs is not None:
                for ref in refs.findall("ref"):
                    if ref.get("type") == "cve":
                        cves.append(ref.get("id", ""))
            # Also check tags for CVE
            tags = nvt.findtext("tags", "")
            cves.extend(re.findall(r"CVE-\d{4}-\d{4,}", tags))
            cves = list(dict.fromkeys(c for c in cves if c.startswith("CVE-")))  # dedupe
            if not cves: return None

            host_elem = result.find("host")
            host_ip = host_elem.text.strip() if host_elem is not None and host_elem.text else ""
            hostname = (host_elem.find("hostname").text or "") if host_elem is not None and host_elem.find("hostname") is not None else ""

            port_str = result.findtext("port", "")
            port = 0; protocol = ""
            if "/" in port_str:
                parts = port_str.split("/")
                try: port = int(parts[0])
                except: pass
                protocol = parts[-1] if len(parts) > 1 else ""

            severity = float(result.findtext("severity", "0"))

            return NormalizedVuln(
                cve_id=cves[0], source_scanner="openvas", source_id=oid,
                cvss_base_score=severity,
                title=nvt.findtext("name", "Unknown")[:500],
                description=result.findtext("description", "")[:2000],
                solution=nvt.findtext("solution", "")[:2000],
                hostname=hostname, ip_address=host_ip,
                port=port, protocol=protocol,
                raw_data={"oid": oid, "all_cves": cves, "qod": result.findtext("qod/value", "")},
            )
        except Exception as e:
            logger.warning(f"OpenVAS normalize failed: {e}"); return None

    async def health_check(self) -> bool: return await self.connect()

    @property
    def provider_name(self) -> str: return "openvas"
