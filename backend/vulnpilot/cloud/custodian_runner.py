"""
VulnPilot AI - Cloud Custodian Integration
Custom YAML policy engine for compliance checks beyond Prowler.

Prowler = pre-built checks (500+ for CIS, SOC2, HIPAA, etc.)
Cloud Custodian = custom policies YOU define in YAML (no code needed)

Example policies:
  - "Flag any EC2 instance running for >90 days without patching"
  - "Alert on S3 buckets without versioning in production accounts"
  - "Ensure all Lambda functions use latest runtime versions"

VulnPilot orchestrates both: Prowler for standard frameworks,
Custodian for org-specific rules that auditors require.

Usage:
  1. Drop YAML policies in config/custodian/
  2. VulnPilot discovers and runs them automatically
  3. Results normalize into the same compliance dashboard as Prowler
"""

import json
import logging
import os
import subprocess
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from vulnpilot.cloud.ocsf_parser import CloudComplianceFinding

logger = logging.getLogger(__name__)


# Sample policies shipped with VulnPilot
BUILTIN_POLICIES = {
    "ec2-public-no-approved-ami": {
        "name": "ec2-public-no-approved-ami",
        "resource": "aws.ec2",
        "description": "Flag public EC2 instances not using approved AMIs",
        "filters": [
            {"type": "value", "key": "PublicIpAddress", "value": "not-null"},
            {"type": "value", "key": "ImageId", "op": "not-in",
             "value_from": {"url": "s3://company-config/approved-amis.json", "format": "json"}},
        ],
        "actions": [{"type": "notify", "to": ["security@company.com"],
                     "transport": {"type": "sqs", "queue": "custodian-alerts"}}],
    },
    "s3-no-versioning": {
        "name": "s3-no-versioning-prod",
        "resource": "aws.s3",
        "description": "Production S3 buckets must have versioning enabled",
        "filters": [
            {"type": "value", "key": "tag:Environment", "value": "production"},
            {"type": "bucket-versioning", "enabled": False},
        ],
    },
    "rds-backup-retention": {
        "name": "rds-backup-retention",
        "resource": "aws.rds",
        "description": "RDS instances must have 7+ day backup retention",
        "filters": [
            {"type": "value", "key": "BackupRetentionPeriod", "op": "less-than", "value": 7},
        ],
    },
    "lambda-outdated-runtime": {
        "name": "lambda-outdated-runtime",
        "resource": "aws.lambda",
        "description": "Lambda functions using deprecated runtimes",
        "filters": [
            {"type": "value", "key": "Runtime", "op": "in",
             "value": ["python3.7", "python3.8", "nodejs14.x", "nodejs16.x",
                       "dotnet6", "ruby2.7", "java8"]},
        ],
    },
    "iam-unused-credentials": {
        "name": "iam-unused-credentials-90d",
        "resource": "aws.iam-user",
        "description": "IAM users with credentials unused for 90+ days",
        "filters": [
            {"type": "credential", "key": "access_keys.last_used_date",
             "value_type": "age", "op": "greater-than", "value": 90},
        ],
    },
}


class CustodianRunner:
    """Runs Cloud Custodian policies and collects results.

    Policies are YAML files in config/custodian/ directory.
    Built-in policies are also available for common checks.
    """

    def __init__(self):
        self.policy_dir = Path(os.getenv("CUSTODIAN_POLICY_DIR", "config/custodian"))
        self.output_dir = Path(os.getenv("CUSTODIAN_OUTPUT_DIR", "/data/custodian"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_builtin_policies(self) -> dict:
        """Return built-in policies that ship with VulnPilot."""
        return BUILTIN_POLICIES

    def get_custom_policies(self) -> list[dict]:
        """Load custom YAML policies from config/custodian/ directory."""
        policies = []
        if not self.policy_dir.exists():
            return policies

        import yaml
        for filepath in self.policy_dir.glob("*.yml"):
            try:
                with open(filepath) as f:
                    doc = yaml.safe_load(f)
                    if doc and "policies" in doc:
                        for p in doc["policies"]:
                            p["_source_file"] = str(filepath)
                            policies.append(p)
            except Exception as e:
                logger.warning(f"Failed to load Custodian policy {filepath}: {e}")

        return policies

    async def run_policy(self, policy_name: str, cloud: str = "aws",
                         dry_run: bool = True) -> list[dict]:
        """Run a single Custodian policy.

        Args:
            policy_name: Name of builtin or custom policy
            cloud: Target cloud (aws, azure, gcp)
            dry_run: If True, only identifies resources (no actions)

        Returns:
            List of non-compliant resources found
        """
        # Find the policy
        policy = BUILTIN_POLICIES.get(policy_name)
        if not policy:
            customs = self.get_custom_policies()
            policy = next((p for p in customs if p.get("name") == policy_name), None)

        if not policy:
            logger.error(f"Policy not found: {policy_name}")
            return []

        # Write temp policy file
        import yaml
        temp_policy = self.output_dir / f"_run_{policy_name}.yml"
        with open(temp_policy, "w") as f:
            yaml.dump({"policies": [policy]}, f)

        # Build custodian command
        output_path = self.output_dir / policy_name
        cmd = ["custodian", "run", "--output-dir", str(output_path)]
        if dry_run:
            cmd.append("--dry-run")
        cmd.append(str(temp_policy))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            if proc.returncode != 0:
                logger.error(f"Custodian policy {policy_name} failed: {stderr.decode()[:500]}")
                return []

            # Parse results
            results = self._parse_results(output_path / policy_name)
            logger.info(f"Custodian {policy_name}: {len(results)} non-compliant resources")
            return results

        except FileNotFoundError:
            logger.warning("Cloud Custodian not installed. Install: pip install c7n")
            return []
        except asyncio.TimeoutError:
            logger.error(f"Custodian policy {policy_name} timed out")
            return []
        except Exception as e:
            logger.error(f"Custodian run failed: {e}")
            return []
        finally:
            temp_policy.unlink(missing_ok=True)

    def _parse_results(self, output_path: Path) -> list[dict]:
        """Parse Custodian output resources.json."""
        resources_file = output_path / "resources.json"
        if not resources_file.exists():
            return []
        try:
            with open(resources_file) as f:
                return json.load(f)
        except Exception:
            return []

    def results_to_findings(self, policy_name: str, policy: dict,
                            resources: list[dict],
                            cloud: str = "aws") -> list[CloudComplianceFinding]:
        """Convert Custodian results to CloudComplianceFinding for dashboard."""
        findings = []
        desc = policy.get("description", policy_name)

        for res in resources:
            res_id = res.get("InstanceId", res.get("BucketName",
                     res.get("DBInstanceIdentifier", res.get("FunctionName",
                     res.get("UserName", str(res.get("id", "")))))))
            res_type = policy.get("resource", "").replace("aws.", "AWS::").replace(".", "::")

            findings.append(CloudComplianceFinding(
                check_id=f"custodian-{policy_name}",
                title=f"[Custom Policy] {desc}",
                description=f"Resource {res_id} does not comply with policy: {desc}",
                severity="high",
                severity_score=7.5,
                status="FAIL",
                frameworks=["Custom Policy"],
                cloud_provider=cloud,
                resource_type=res_type,
                resource_id=str(res_id),
                resource_name=str(res_id),
                resource_region=res.get("Region", res.get("Placement", {}).get("AvailabilityZone", "")[:9]),
                remediation=f"Address non-compliance with policy '{policy_name}': {desc}",
                scan_timestamp=datetime.utcnow(),
                raw_ocsf={"source": "cloud_custodian", "policy": policy_name, "resource": res},
            ))

        return findings
