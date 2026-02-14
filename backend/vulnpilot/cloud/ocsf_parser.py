"""
VulnPilot AI - OCSF Parser
Parses Prowler OCSF (Open Cybersecurity Schema Framework) v1.1 output
into VulnPilot's internal format for compliance findings.

OCSF is the standard output from Prowler 3.x+.
Each finding is a JSON object per line (JSON Lines format).

Key OCSF fields:
  - class_uid: 2001 (Security Finding)
  - severity_id: 1-4 (Low, Medium, High, Critical)
  - finding_info.title: Finding title
  - finding_info.uid: Unique ID (e.g., prowler-aws-iam_root_access_key_check)
  - compliance.requirements[]: Framework mappings (CIS 1.5, SOC2, HIPAA, etc.)
  - remediation.description: Fix instructions
  - resources[]: Affected cloud resources with ARN/ID
  - status_id: 1=New, 2=Active, 99=Other
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CloudComplianceFinding:
    """Normalized cloud compliance finding from Prowler OCSF output."""

    # Finding identity
    check_id: str                    # prowler-aws-iam_root_access_key_check
    title: str                       # "IAM Root Access Key exists"
    description: str = ""
    severity: str = "medium"         # critical, high, medium, low
    severity_score: float = 5.0      # 0-10 normalized

    # Status
    status: str = "FAIL"             # PASS, FAIL, MANUAL, WARNING
    status_detail: str = ""

    # Compliance mapping
    frameworks: list[str] = field(default_factory=list)   # ["CIS 1.5 - 1.4", "SOC2 CC6.1"]
    requirements: list[str] = field(default_factory=list)  # Raw requirement IDs

    # Affected resource
    cloud_provider: str = "aws"      # aws, azure, gcp
    resource_type: str = ""          # AWS::IAM::User, Azure::Storage::Account
    resource_id: str = ""            # arn:aws:iam::123456:root
    resource_name: str = ""
    resource_region: str = ""
    account_id: str = ""

    # Remediation
    remediation: str = ""
    remediation_url: str = ""

    # Metadata
    scan_timestamp: Optional[datetime] = None
    raw_ocsf: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "status": self.status,
            "frameworks": self.frameworks,
            "cloud_provider": self.cloud_provider,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_region": self.resource_region,
            "account_id": self.account_id,
            "remediation": self.remediation[:500],
            "description": self.description[:500],
        }


class OCSFParser:
    """Parses Prowler OCSF JSON output into CloudComplianceFinding objects."""

    SEVERITY_MAP = {
        0: ("informational", 0.0),
        1: ("low", 2.5),
        2: ("medium", 5.0),
        3: ("high", 7.5),
        4: ("critical", 9.5),
        99: ("other", 3.0),
    }

    STATUS_MAP = {
        1: "PASS",
        2: "FAIL",
        3: "WARNING",
        4: "MANUAL",
        99: "OTHER",
    }

    def parse_file(self, filepath: str) -> list[CloudComplianceFinding]:
        """Parse an OCSF JSON Lines file from Prowler."""
        findings = []
        path = Path(filepath)

        if not path.exists():
            logger.error(f"OCSF file not found: {filepath}")
            return []

        try:
            with open(path) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        finding = self._parse_record(record)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError as e:
                        logger.warning(f"OCSF parse error line {line_num}: {e}")
                    except Exception as e:
                        logger.warning(f"OCSF normalize error line {line_num}: {e}")

            logger.info(f"Parsed {len(findings)} findings from {filepath}")
        except Exception as e:
            logger.error(f"Failed to read OCSF file {filepath}: {e}")

        return findings

    def parse_json_array(self, data: list[dict]) -> list[CloudComplianceFinding]:
        """Parse a list of OCSF records (for API/sample data)."""
        findings = []
        for record in data:
            finding = self._parse_record(record)
            if finding:
                findings.append(finding)
        return findings

    def _parse_record(self, record: dict) -> Optional[CloudComplianceFinding]:
        """Parse a single OCSF record into a CloudComplianceFinding."""
        # Only process Security Findings (class_uid 2001)
        class_uid = record.get("class_uid", 0)
        if class_uid not in (2001, 2002, 2004):  # Security Finding, Compliance, Detection
            return None

        finding_info = record.get("finding_info", {})
        severity_id = record.get("severity_id", 2)
        severity_name, severity_score = self.SEVERITY_MAP.get(severity_id, ("medium", 5.0))

        status_id = record.get("status_id", 2)
        status = self.STATUS_MAP.get(status_id, "FAIL")

        # Extract compliance framework mappings
        compliance = record.get("compliance", {})
        frameworks = []
        requirements = []
        for req in compliance.get("requirements", []):
            if isinstance(req, dict):
                name = req.get("name", "")
                uid = req.get("uid", "")
                if name:
                    frameworks.append(name)
                if uid:
                    requirements.append(uid)
            elif isinstance(req, str):
                frameworks.append(req)
                requirements.append(req)

        # Extract affected resource
        resources = record.get("resources", [])
        resource = resources[0] if resources else {}
        resource_id = resource.get("uid", "") or resource.get("cloud_partition", "")
        resource_name = resource.get("name", "")
        resource_type = resource.get("type", "")
        resource_region = resource.get("region", "")
        account_uid = resource.get("account", {}).get("uid", "") if isinstance(resource.get("account"), dict) else ""

        # Cloud provider detection
        cloud_provider = "aws"  # default
        metadata = record.get("metadata", {})
        product = metadata.get("product", {})
        if "azure" in str(product).lower():
            cloud_provider = "azure"
        elif "gcp" in str(product).lower() or "google" in str(product).lower():
            cloud_provider = "gcp"

        # Remediation
        remediation = record.get("remediation", {})
        remediation_desc = remediation.get("description", "")
        remediation_url = ""
        refs = remediation.get("references", [])
        if refs:
            remediation_url = refs[0] if isinstance(refs[0], str) else refs[0].get("url", "")

        # Timestamp
        time_dt = record.get("time_dt")
        scan_ts = None
        if time_dt:
            try:
                scan_ts = datetime.fromisoformat(time_dt.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        return CloudComplianceFinding(
            check_id=finding_info.get("uid", "") or record.get("finding", {}).get("uid", ""),
            title=finding_info.get("title", "") or record.get("message", "Unknown"),
            description=finding_info.get("desc", "") or record.get("finding", {}).get("desc", ""),
            severity=severity_name,
            severity_score=severity_score,
            status=status,
            status_detail=record.get("status_detail", ""),
            frameworks=frameworks,
            requirements=requirements,
            cloud_provider=cloud_provider,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_region=resource_region,
            account_id=account_uid,
            remediation=remediation_desc[:2000],
            remediation_url=remediation_url,
            scan_timestamp=scan_ts,
            raw_ocsf=record,
        )

    def get_summary(self, findings: list[CloudComplianceFinding]) -> dict:
        """Generate summary statistics from parsed findings."""
        total = len(findings)
        by_status = {}
        by_severity = {}
        by_framework = {}
        by_resource_type = {}
        by_region = {}

        for f in findings:
            by_status[f.status] = by_status.get(f.status, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            for fw in f.frameworks:
                by_framework[fw] = by_framework.get(fw, 0) + 1
            if f.resource_type:
                by_resource_type[f.resource_type] = by_resource_type.get(f.resource_type, 0) + 1
            if f.resource_region:
                by_region[f.resource_region] = by_region.get(f.resource_region, 0) + 1

        fail_count = by_status.get("FAIL", 0)
        pass_count = by_status.get("PASS", 0)
        compliance_pct = round(pass_count / total * 100, 1) if total > 0 else 0

        return {
            "total_findings": total,
            "compliance_percentage": compliance_pct,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "by_status": by_status,
            "by_severity": by_severity,
            "top_frameworks": dict(sorted(by_framework.items(), key=lambda x: -x[1])[:10]),
            "top_resource_types": dict(sorted(by_resource_type.items(), key=lambda x: -x[1])[:10]),
            "regions_scanned": list(by_region.keys()),
        }
