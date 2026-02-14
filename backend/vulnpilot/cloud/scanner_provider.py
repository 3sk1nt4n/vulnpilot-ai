"""
VulnPilot AI - Cloud Scanner Provider
Integrates Prowler compliance scanning + cloud asset inventory
into VulnPilot's existing scanner factory pattern.

This is the bridge between cloud infrastructure and VulnPilot's pipeline.
It runs Prowler, parses OCSF output, collects cloud assets, and normalizes
everything into NormalizedVuln format for VPRS scoring.

SCANNER_PROVIDERS=cloud          → Cloud-only mode
SCANNER_PROVIDERS=tenable,cloud  → Commercial VM + cloud compliance
"""

import logging
import os
from datetime import datetime
from typing import Optional

from vulnpilot.scanners.base import ScannerProvider, NormalizedVuln
from vulnpilot.cloud.ocsf_parser import OCSFParser, CloudComplianceFinding
from vulnpilot.cloud.prowler_runner import ProwlerRunner

logger = logging.getLogger(__name__)


class CloudScannerProvider(ScannerProvider):
    """Cloud compliance scanner that wraps Prowler + asset collectors.

    Plugs into the existing scanner factory:
      SCANNER_PROVIDERS=cloud → factory loads this provider

    Two data modes:
    1. Live: Runs Prowler scan against real cloud account
    2. Demo: Loads sample OCSF data from data/prowler_sample/
    """

    def __init__(self):
        self.prowler = ProwlerRunner()
        self.parser = OCSFParser()
        self.demo_mode = os.getenv("CLOUD_DEMO_MODE", "true").lower() == "true"
        self.sample_dir = os.getenv("PROWLER_SAMPLE_DIR", "data/prowler_sample")
        self.cloud = os.getenv("CLOUD_PROVIDER", "aws")

    async def connect(self) -> bool:
        """Test cloud connectivity."""
        if self.demo_mode:
            logger.info("Cloud scanner: DEMO MODE (using sample Prowler data)")
            return True

        try:
            from vulnpilot.cloud.credentials import CredentialManager
            cm = CredentialManager()
            creds = await cm.validate_all()
            valid = [p for p, c in creds.items() if c.is_valid]
            if valid:
                logger.info(f"Cloud scanner: connected to {', '.join(valid)}")
                return True
            logger.warning("Cloud scanner: no valid cloud credentials found")
            return False
        except Exception as e:
            logger.error(f"Cloud scanner connect failed: {e}")
            return False

    async def fetch_vulnerabilities(
        self, since: Optional[datetime] = None
    ) -> list[NormalizedVuln]:
        """Fetch cloud compliance findings as NormalizedVuln.

        In demo mode: reads sample OCSF file.
        In live mode: triggers Prowler scan, parses output.
        """
        findings: list[CloudComplianceFinding] = []

        if self.demo_mode:
            findings = self._load_sample_data()
        else:
            findings = await self._run_live_scan()

        # Convert CloudComplianceFinding → NormalizedVuln
        results = []
        for f in findings:
            if f.status != "FAIL":  # Only include failures
                continue
            normed = self._to_normalized_vuln(f)
            if normed:
                results.append(normed)

        logger.info(f"Cloud scanner: {len(results)} compliance findings "
                   f"(from {len(findings)} total, {'demo' if self.demo_mode else 'live'} mode)")
        return results

    def _load_sample_data(self) -> list[CloudComplianceFinding]:
        """Load sample Prowler OCSF data for demo mode."""
        import glob
        findings = []
        for filepath in glob.glob(f"{self.sample_dir}/*.ocsf.json"):
            findings.extend(self.parser.parse_file(filepath))
        if not findings:
            logger.warning(f"No sample data found in {self.sample_dir}")
        return findings

    async def _run_live_scan(self) -> list[CloudComplianceFinding]:
        """Run live Prowler scan and parse results."""
        result = await self.prowler.run_scan(
            cloud=self.cloud,
            severity="critical,high,medium",
        )
        if result["status"] != "completed":
            logger.error(f"Prowler scan failed: {result.get('error', 'unknown')}")
            return []

        return self.parser.parse_file(result["output_path"])

    def _to_normalized_vuln(self, finding: CloudComplianceFinding) -> Optional[NormalizedVuln]:
        """Convert a cloud compliance finding to NormalizedVuln for VPRS scoring."""
        try:
            # Use check_id as a pseudo-CVE for compliance findings
            # Format: CLOUD-{provider}-{check_id}
            pseudo_cve = f"CLOUD-{finding.cloud_provider.upper()}-{finding.check_id}"

            # Map compliance severity to CVSS-like score
            severity_cvss = {
                "critical": 9.5, "high": 7.5, "medium": 5.0,
                "low": 2.5, "informational": 1.0,
            }

            return NormalizedVuln(
                cve_id=pseudo_cve,
                source_scanner=f"prowler_{finding.cloud_provider}",
                source_id=finding.check_id,
                cvss_base_score=severity_cvss.get(finding.severity, 5.0),
                title=finding.title[:500],
                description=finding.description[:2000],
                solution=finding.remediation[:2000],
                hostname=finding.resource_name,
                ip_address="",  # Cloud resources don't always have IPs
                raw_data={
                    "type": "cloud_compliance",
                    "cloud_provider": finding.cloud_provider,
                    "resource_type": finding.resource_type,
                    "resource_id": finding.resource_id,
                    "resource_region": finding.resource_region,
                    "account_id": finding.account_id,
                    "frameworks": finding.frameworks,
                    "requirements": finding.requirements,
                    "status": finding.status,
                    "remediation_url": finding.remediation_url,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to convert cloud finding: {e}")
            return None

    async def health_check(self) -> bool:
        return await self.connect()

    @property
    def provider_name(self) -> str:
        return "cloud"
