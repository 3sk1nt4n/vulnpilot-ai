"""
VulnPilot AI - Prowler Integration Runner
Runs Prowler in Docker for cloud compliance scanning (500+ checks, 39 frameworks).

Architecture:
  VulnPilot → triggers Prowler scan → Prowler runs in sibling container
  → output as OCSF JSON → OCSF parser normalizes → VulnPilot pipeline

Prowler runs as a Docker service in the VulnPilot stack.
Credentials are passed via env vars or IAM role (recommended).

Supported clouds: AWS, Azure, GCP
Output format: OCSF v1.1 (Open Cybersecurity Schema Framework)
"""

import asyncio
import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Where Prowler writes results
PROWLER_OUTPUT_DIR = os.getenv("PROWLER_OUTPUT_DIR", "/data/prowler")


class ProwlerRunner:
    """Manages Prowler scan execution and result collection.

    Two modes:
    1. Docker mode (production): Runs prowler as sibling container via docker exec
    2. CLI mode (dev): Runs prowler CLI directly if installed
    """

    def __init__(self):
        self.output_dir = Path(PROWLER_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.docker_image = os.getenv("PROWLER_IMAGE", "toniblyx/prowler:latest")
        self.container_name = os.getenv("PROWLER_CONTAINER", "vulnpilot-prowler")
        self._running = False
        self._last_scan: Optional[datetime] = None
        self._last_result_path: Optional[Path] = None

    async def run_scan(
        self,
        cloud: str = "aws",
        profile: str = "",
        region: str = "",
        framework: str = "",
        checks: list[str] = None,
        severity: str = "critical,high,medium",
    ) -> dict:
        """Trigger a Prowler scan.

        Args:
            cloud: aws, azure, or gcp
            profile: AWS profile name or Azure subscription ID
            region: Specific region(s) to scan (comma-separated)
            framework: Specific compliance framework (e.g., cis_1.5, soc2, hipaa)
            checks: Specific check IDs to run (empty = all)
            severity: Filter by severity level

        Returns:
            {"status": "completed", "output_path": "/data/prowler/...", "findings_count": 42}
        """
        if self._running:
            return {"status": "error", "error": "Scan already in progress"}

        self._running = True
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"prowler_{cloud}_{timestamp}"

        try:
            cmd = self._build_command(
                cloud=cloud, profile=profile, region=region,
                framework=framework, checks=checks,
                severity=severity, output_path=str(output_file),
            )

            logger.info(f"Starting Prowler {cloud} scan: {' '.join(cmd[:8])}...")

            # Run Prowler (async subprocess)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=3600  # 1 hour max
            )

            if proc.returncode not in (0, 2):  # 2 = findings found (expected)
                logger.error(f"Prowler failed (exit {proc.returncode}): {stderr.decode()[:500]}")
                return {"status": "error", "error": stderr.decode()[:500]}

            # Find the OCSF output file
            ocsf_file = self._find_ocsf_output(output_file)
            if not ocsf_file:
                return {"status": "error", "error": "No OCSF output file found"}

            # Count findings
            findings_count = self._count_findings(ocsf_file)
            self._last_scan = datetime.utcnow()
            self._last_result_path = ocsf_file

            logger.info(f"Prowler scan completed: {findings_count} findings in {ocsf_file}")
            return {
                "status": "completed",
                "output_path": str(ocsf_file),
                "findings_count": findings_count,
                "cloud": cloud,
                "timestamp": timestamp,
            }

        except asyncio.TimeoutError:
            logger.error("Prowler scan timed out (1h limit)")
            return {"status": "error", "error": "Scan timed out after 1 hour"}
        except FileNotFoundError:
            logger.error("Prowler not found. Ensure prowler is installed or Docker image is available.")
            return {"status": "error", "error": "Prowler not found. Check Docker image or PATH."}
        except Exception as e:
            logger.error(f"Prowler scan failed: {e}")
            return {"status": "error", "error": str(e)}
        finally:
            self._running = False

    def _build_command(self, cloud: str, profile: str, region: str,
                       framework: str, checks: list, severity: str,
                       output_path: str) -> list[str]:
        """Build Prowler CLI command."""
        cmd = ["prowler", cloud]

        # Output format: OCSF JSON (machine-readable)
        cmd.extend(["-M", "ocsf-json"])
        cmd.extend(["-o", output_path])

        # Filters
        if severity:
            cmd.extend(["--severity", severity])
        if framework:
            cmd.extend(["--compliance", framework])
        if checks:
            cmd.extend(["--checks", ",".join(checks)])

        # Cloud-specific options
        if cloud == "aws":
            if profile:
                cmd.extend(["--profile", profile])
            if region:
                cmd.extend(["--filter-region", region])
            role_arn = os.getenv("AWS_PROWLER_ROLE_ARN", "")
            if role_arn:
                cmd.extend(["--role", role_arn])
        elif cloud == "azure":
            sub_id = profile or os.getenv("AZURE_SUBSCRIPTION_ID", "")
            if sub_id:
                cmd.extend(["--subscription-ids", sub_id])
        elif cloud == "gcp":
            project = profile or os.getenv("GCP_PROJECT_ID", "")
            if project:
                cmd.extend(["--project-ids", project])

        # Quiet mode (less terminal noise)
        cmd.append("--no-banner")

        return cmd

    def _find_ocsf_output(self, base_path: Path) -> Optional[Path]:
        """Find the OCSF JSON output file Prowler created."""
        parent = base_path.parent
        name_prefix = base_path.name

        # Prowler creates files like: prowler_aws_20240101_120000.ocsf.json
        for f in sorted(parent.glob(f"{name_prefix}*ocsf*.json"), reverse=True):
            return f

        # Also check standard Prowler output directory structure
        for f in sorted(parent.glob("**/*.ocsf.json"), reverse=True):
            return f

        return None

    def _count_findings(self, path: Path) -> int:
        """Count findings in OCSF JSON file."""
        try:
            count = 0
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            json.loads(line)
                            count += 1
                        except json.JSONDecodeError:
                            pass
            return count
        except Exception:
            return 0

    def get_last_scan_info(self) -> dict:
        return {
            "last_scan": self._last_scan.isoformat() if self._last_scan else None,
            "last_result": str(self._last_result_path) if self._last_result_path else None,
            "is_running": self._running,
        }

    async def get_available_frameworks(self, cloud: str = "aws") -> list[str]:
        """List available compliance frameworks for a cloud."""
        frameworks = {
            "aws": [
                "cis_1.4_aws", "cis_1.5_aws", "cis_2.0_aws", "cis_3.0_aws",
                "aws_well_architected_framework_security_pillar",
                "aws_foundational_security_best_practices",
                "aws_audit_manager_control_tower_guardrails",
                "soc2_aws", "hipaa_aws", "pci_3.2.1_aws", "gdpr_aws",
                "nist_800_53_revision_5_aws", "nist_800_171_revision_2_aws",
                "nist_csf_1.1_aws", "fedramp_low_revision_4_aws",
                "fedramp_moderate_revision_4_aws", "iso27001_2013_aws",
                "ens_rd2022_aws", "mitre_attack_aws",
            ],
            "azure": [
                "cis_1.1_azure", "cis_2.0_azure", "cis_2.1_azure",
                "soc2_azure", "hipaa_azure", "pci_3.2.1_azure",
                "nist_800_53_revision_5_azure", "mitre_attack_azure",
            ],
            "gcp": [
                "cis_1.2_gcp", "cis_2.0_gcp",
                "soc2_gcp", "hipaa_gcp", "pci_3.2.1_gcp",
                "nist_800_53_revision_5_gcp", "mitre_attack_gcp",
            ],
        }
        return frameworks.get(cloud, [])
