"""
VulnPilot AI - Nessus File Scanner Provider
Parses .nessus XML export files for offline/air-gapped scanning.
Supports bulk import of historical scan data.
"""

import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from defusedxml import ElementTree as ET

from vulnpilot.scanners.base import ScannerProvider, NormalizedVuln

logger = logging.getLogger(__name__)


class NessusFileProvider(ScannerProvider):
    """Parse .nessus XML files from Tenable Nessus exports."""

    def __init__(self):
        self.scan_dir = os.getenv("NESSUS_FILE_PATH", "./data/sample_scans/")

    async def connect(self) -> bool:
        path = Path(self.scan_dir)
        if path.exists() and path.is_dir():
            nessus_files = list(path.glob("*.nessus"))
            logger.info(f"Found {len(nessus_files)} .nessus files in {self.scan_dir}")
            return len(nessus_files) > 0
        logger.warning(f"Nessus scan directory not found: {self.scan_dir}")
        return False

    async def fetch_vulnerabilities(
        self, since: Optional[datetime] = None
    ) -> list[NormalizedVuln]:
        """Parse all .nessus files in the configured directory."""
        results = []
        scan_dir = Path(self.scan_dir)

        if not scan_dir.exists():
            logger.warning(f"Scan directory does not exist: {self.scan_dir}")
            return results

        for nessus_file in scan_dir.glob("*.nessus"):
            try:
                file_results = self._parse_nessus_file(str(nessus_file))
                results.extend(file_results)
                logger.info(f"Parsed {len(file_results)} vulns from {nessus_file.name}")
            except Exception as e:
                logger.error(f"Failed to parse {nessus_file}: {e}")

        logger.info(f"Total: {len(results)} vulnerabilities from .nessus files")
        return results

    def _parse_nessus_file(self, filepath: str) -> list[NormalizedVuln]:
        """Parse a single .nessus XML file."""
        results = []
        tree = ET.parse(filepath)
        root = tree.getroot()

        for report_host in root.findall(".//ReportHost"):
            hostname = report_host.get("name", "")
            ip_address = ""
            os_name = ""

            # Extract host properties
            for tag in report_host.findall(".//HostProperties/tag"):
                tag_name = tag.get("name", "")
                if tag_name == "host-ip":
                    ip_address = tag.text or ""
                elif tag_name == "operating-system":
                    os_name = tag.text or ""
                elif tag_name == "host-fqdn" and not hostname:
                    hostname = tag.text or ""

            # Process each finding
            for item in report_host.findall(".//ReportItem"):
                normalized = self._normalize_item(item, hostname, ip_address, os_name)
                if normalized:
                    results.append(normalized)

        return results

    def _normalize_item(
        self, item: ET.Element, hostname: str, ip: str, os_name: str
    ) -> Optional[NormalizedVuln]:
        """Normalize a Nessus ReportItem to NormalizedVuln."""
        try:
            # Extract CVE(s)
            cves = [cve.text for cve in item.findall("cve") if cve.text]
            if not cves:
                return None
            cve_id = cves[0]

            # Extract CVSS
            cvss3 = item.findtext("cvss3_base_score", "")
            cvss2 = item.findtext("cvss_base_score", "")
            cvss_score = float(cvss3 or cvss2 or "0")

            port = int(item.get("port", "0"))
            protocol = item.get("protocol", "")
            plugin_id = item.get("pluginID", "")

            return NormalizedVuln(
                cve_id=cve_id,
                source_scanner="nessus_file",
                source_id=plugin_id,
                cvss_base_score=cvss_score,
                cvss_vector=item.findtext("cvss3_vector", item.findtext("cvss_vector", "")),
                cvss_version="3.1" if cvss3 else "2.0",
                title=item.get("pluginName", "Unknown")[:500],
                description=item.findtext("description", "")[:2000],
                solution=item.findtext("solution", "")[:2000],
                cwe_id=item.findtext("cwe", ""),
                hostname=hostname,
                ip_address=ip,
                port=port,
                protocol=protocol,
                os=os_name,
                software=item.findtext("plugin_output", "")[:500],
                raw_data={
                    "plugin_id": plugin_id,
                    "severity": item.get("severity", "0"),
                    "all_cves": cves,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to normalize Nessus item: {e}")
            return None

    async def health_check(self) -> bool:
        return Path(self.scan_dir).exists()

    @property
    def provider_name(self) -> str:
        return "nessus_file"
