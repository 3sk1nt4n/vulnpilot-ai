"""
VulnPilot AI - Cloud Module Tests
Tests: OCSF parser, cloud scanner provider, credential manager, Prowler runner, Custodian runner.
Run: pytest tests/test_cloud.py -v
"""

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock


# ═══════════════════════════════════════
# OCSF Parser Tests
# ═══════════════════════════════════════

class TestOCSFParser:
    """Test OCSF JSON Lines parser."""

    def _sample_record(self, status_id=2, severity_id=4, cve="prowler-aws-iam_root_mfa"):
        return {
            "class_uid": 2001,
            "severity_id": severity_id,
            "status_id": status_id,
            "finding_info": {
                "uid": cve,
                "title": "Root MFA not enabled",
                "desc": "Root account missing MFA",
            },
            "compliance": {
                "requirements": [
                    {"name": "CIS 1.5 - 1.6", "uid": "cis_1.5_aws-1.6"},
                    {"name": "SOC2 CC6.1", "uid": "soc2-cc6.1"},
                ]
            },
            "resources": [{
                "uid": "arn:aws:iam::123456:root",
                "name": "root",
                "type": "AWS::IAM::User",
                "region": "us-east-1",
                "account": {"uid": "123456789012"},
            }],
            "remediation": {"description": "Enable MFA for root account"},
            "time_dt": "2026-02-14T00:00:00Z",
            "metadata": {"product": {"name": "Prowler", "vendor_name": "Prowler"}},
        }

    def test_parse_single_record(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        result = parser._parse_record(self._sample_record())
        assert result is not None
        assert result.check_id == "prowler-aws-iam_root_mfa"
        assert result.title == "Root MFA not enabled"
        assert result.severity == "critical"
        assert result.severity_score == 9.5
        assert result.status == "FAIL"
        assert len(result.frameworks) == 2
        assert "CIS 1.5 - 1.6" in result.frameworks
        assert result.resource_type == "AWS::IAM::User"
        assert result.cloud_provider == "aws"

    def test_parse_pass_status(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        record = self._sample_record(status_id=1)  # PASS
        result = parser._parse_record(record)
        assert result.status == "PASS"

    def test_parse_severity_levels(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        for sev_id, expected_name, expected_score in [
            (1, "low", 2.5), (2, "medium", 5.0), (3, "high", 7.5), (4, "critical", 9.5)
        ]:
            result = parser._parse_record(self._sample_record(severity_id=sev_id))
            assert result.severity == expected_name, f"Expected {expected_name} for severity_id {sev_id}"
            assert result.severity_score == expected_score

    def test_parse_file(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ocsf.json", delete=False) as f:
            f.write(json.dumps(self._sample_record()) + "\n")
            f.write(json.dumps(self._sample_record(status_id=1)) + "\n")
            f.write(json.dumps(self._sample_record(severity_id=3)) + "\n")
            f.flush()
            findings = parser.parse_file(f.name)
        os.unlink(f.name)
        assert len(findings) == 3

    def test_parse_file_not_found(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        findings = parser.parse_file("/nonexistent/file.json")
        assert findings == []

    def test_get_summary(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        records = [
            self._sample_record(status_id=2, severity_id=4),  # FAIL critical
            self._sample_record(status_id=2, severity_id=3),  # FAIL high
            self._sample_record(status_id=1, severity_id=4),  # PASS critical
        ]
        findings = parser.parse_json_array(records)
        summary = parser.get_summary(findings)
        assert summary["total_findings"] == 3
        assert summary["pass_count"] == 1
        assert summary["fail_count"] == 2
        assert summary["compliance_percentage"] == pytest.approx(33.3, abs=0.1)

    def test_skip_non_security_finding(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        record = self._sample_record()
        record["class_uid"] = 9999  # Not a security finding
        result = parser._parse_record(record)
        assert result is None

    def test_to_dict(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        finding = parser._parse_record(self._sample_record())
        d = finding.to_dict()
        assert d["check_id"] == "prowler-aws-iam_root_mfa"
        assert d["severity"] == "critical"
        assert "frameworks" in d

    def test_parse_file_skips_empty_lines(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ocsf.json", delete=False) as f:
            f.write(json.dumps(self._sample_record()) + "\n")
            f.write("\n")  # empty line
            f.write("   \n")  # whitespace-only line
            f.write(json.dumps(self._sample_record()) + "\n")
            f.flush()
            findings = parser.parse_file(f.name)
        os.unlink(f.name)
        assert len(findings) == 2

    def test_parse_file_handles_json_decode_error(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ocsf.json", delete=False) as f:
            f.write(json.dumps(self._sample_record()) + "\n")
            f.write("{invalid json}\n")  # malformed JSON
            f.write(json.dumps(self._sample_record()) + "\n")
            f.flush()
            findings = parser.parse_file(f.name)
        os.unlink(f.name)
        assert len(findings) == 2  # skips bad line, keeps good ones

    def test_parse_file_handles_normalize_error(self):
        """Valid JSON that crashes during _parse_record (lines 126-127)."""
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ocsf.json", delete=False) as f:
            f.write(json.dumps(self._sample_record()) + "\n")
            # Valid JSON but resources is a string, so resources[0].get() will
            # raise AttributeError during normalization
            bad_record = self._sample_record()
            bad_record["resources"] = "not-a-list"
            f.write(json.dumps(bad_record) + "\n")
            f.flush()
            findings = parser.parse_file(f.name)
        os.unlink(f.name)
        assert len(findings) == 1  # good record kept, bad one skipped

    def test_parse_file_read_error(self):
        """Outer exception handler for file read errors (lines 130-131)."""
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".ocsf.json", delete=False) as f:
            # Write invalid UTF-8 bytes to trigger a read error
            f.write(b'\x80\x81\x82\n')
            f.flush()
            findings = parser.parse_file(f.name)
        os.unlink(f.name)
        # Should return empty list or partial results without crashing
        assert isinstance(findings, list)

    def test_string_requirements_in_compliance(self):
        """String-type compliance requirements (lines 170-172)."""
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        record = self._sample_record()
        record["compliance"] = {
            "requirements": ["CIS 1.5 - 1.4", "SOC2 CC6.1"]
        }
        finding = parser._parse_record(record)
        assert "CIS 1.5 - 1.4" in finding.frameworks
        assert "SOC2 CC6.1" in finding.requirements

    def test_azure_cloud_detection(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        record = self._sample_record()
        record["metadata"] = {"product": {"name": "Prowler", "vendor_name": "Azure Prowler"}}
        finding = parser._parse_record(record)
        assert finding.cloud_provider == "azure"

    def test_gcp_cloud_detection(self):
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        record = self._sample_record()
        record["metadata"] = {"product": {"name": "Prowler", "vendor_name": "Google Cloud"}}
        finding = parser._parse_record(record)
        assert finding.cloud_provider == "gcp"

    def test_invalid_timestamp(self):
        """Invalid timestamp should be handled gracefully (lines 206-207)."""
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        record = self._sample_record()
        record["time_dt"] = "not-a-valid-timestamp"
        finding = parser._parse_record(record)
        assert finding is not None
        assert finding.scan_timestamp is None

    def test_parse_sample_data(self):
        """Test parsing the actual sample OCSF data file."""
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        sample_path = "data/prowler_sample/prowler_aws_sample.ocsf.json"
        if os.path.exists(sample_path):
            findings = parser.parse_file(sample_path)
            assert len(findings) == 10  # 7 FAIL + 3 PASS
            summary = parser.get_summary(findings)
            assert summary["fail_count"] == 7
            assert summary["pass_count"] == 3


# ═══════════════════════════════════════
# Cloud Scanner Provider Tests
# ═══════════════════════════════════════

class TestCloudScannerProvider:
    """Test the cloud scanner provider (demo mode)."""

    def test_provider_name(self):
        from vulnpilot.cloud.scanner_provider import CloudScannerProvider
        provider = CloudScannerProvider()
        assert provider.provider_name == "cloud"

    @pytest.mark.asyncio
    async def test_connect_demo_mode(self):
        from vulnpilot.cloud.scanner_provider import CloudScannerProvider
        with patch.dict(os.environ, {"CLOUD_DEMO_MODE": "true"}):
            provider = CloudScannerProvider()
            assert await provider.connect() is True

    @pytest.mark.asyncio
    async def test_fetch_demo_data(self):
        from vulnpilot.cloud.scanner_provider import CloudScannerProvider
        with patch.dict(os.environ, {
            "CLOUD_DEMO_MODE": "true",
            "PROWLER_SAMPLE_DIR": "data/prowler_sample",
        }):
            provider = CloudScannerProvider()
            if os.path.exists("data/prowler_sample/prowler_aws_sample.ocsf.json"):
                vulns = await provider.fetch_vulnerabilities()
                assert len(vulns) == 7  # Only FAIL findings
                for v in vulns:
                    assert v.source_scanner.startswith("prowler_")
                    assert v.cve_id.startswith("CLOUD-")


# ═══════════════════════════════════════
# Credential Manager Tests
# ═══════════════════════════════════════

class TestCredentialManager:
    """Test cloud credential validation."""

    @pytest.mark.asyncio
    async def test_no_credentials(self):
        from vulnpilot.cloud.credentials import CredentialManager
        with patch.dict(os.environ, {}, clear=True):
            cm = CredentialManager()
            results = await cm.validate_all()
            assert not results["aws"].is_valid
            assert not results["azure"].is_valid
            assert not results["gcp"].is_valid

    @pytest.mark.asyncio
    async def test_azure_missing_fields(self):
        from vulnpilot.cloud.credentials import CredentialManager
        with patch.dict(os.environ, {"AZURE_TENANT_ID": "test"}, clear=True):
            cm = CredentialManager()
            result = await cm.validate_azure()
            assert not result.is_valid
            assert "Missing" in result.error

    def test_env_template(self):
        from vulnpilot.cloud.credentials import CredentialManager
        cm = CredentialManager()
        aws_template = cm.get_env_template("aws")
        assert "AWS_ACCESS_KEY_ID" in aws_template
        assert "AWS_DEFAULT_REGION" in aws_template
        azure_template = cm.get_env_template("azure")
        assert "AZURE_TENANT_ID" in azure_template


# ═══════════════════════════════════════
# Prowler Runner Tests
# ═══════════════════════════════════════

class TestProwlerRunner:
    """Test Prowler runner command building."""

    def test_build_aws_command(self):
        from vulnpilot.cloud.prowler_runner import ProwlerRunner
        runner = ProwlerRunner()
        cmd = runner._build_command(
            cloud="aws", profile="", region="us-east-1",
            framework="cis_2.0_aws", checks=None,
            severity="critical,high", output_path="/tmp/test",
        )
        assert cmd[0] == "prowler"
        assert cmd[1] == "aws"
        assert "-M" in cmd
        assert "ocsf-json" in cmd
        assert "--severity" in cmd
        assert "--compliance" in cmd
        assert "--filter-region" in cmd

    def test_build_azure_command(self):
        from vulnpilot.cloud.prowler_runner import ProwlerRunner
        with patch.dict(os.environ, {"AZURE_SUBSCRIPTION_ID": "sub-123"}):
            runner = ProwlerRunner()
            cmd = runner._build_command(
                cloud="azure", profile="sub-123", region="",
                framework="", checks=None,
                severity="critical,high", output_path="/tmp/test",
            )
            assert cmd[1] == "azure"
            assert "--subscription-ids" in cmd

    def test_get_last_scan_info_empty(self):
        from vulnpilot.cloud.prowler_runner import ProwlerRunner
        runner = ProwlerRunner()
        info = runner.get_last_scan_info()
        assert info["last_scan"] is None
        assert info["is_running"] is False

    @pytest.mark.asyncio
    async def test_get_frameworks(self):
        from vulnpilot.cloud.prowler_runner import ProwlerRunner
        runner = ProwlerRunner()
        aws_fws = await runner.get_available_frameworks("aws")
        assert len(aws_fws) > 10
        assert any("cis" in fw for fw in aws_fws)
        azure_fws = await runner.get_available_frameworks("azure")
        assert len(azure_fws) > 3
        gcp_fws = await runner.get_available_frameworks("gcp")
        assert len(gcp_fws) > 3


# ═══════════════════════════════════════
# Custodian Runner Tests
# ═══════════════════════════════════════

class TestCustodianRunner:
    """Test Cloud Custodian policy management."""

    def test_builtin_policies(self):
        from vulnpilot.cloud.custodian_runner import CustodianRunner
        runner = CustodianRunner()
        policies = runner.get_builtin_policies()
        assert len(policies) == 5
        assert "ec2-public-no-approved-ami" in policies
        assert "s3-no-versioning" in policies
        assert "lambda-outdated-runtime" in policies

    def test_custom_policies_empty_dir(self):
        from vulnpilot.cloud.custodian_runner import CustodianRunner
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CustodianRunner()
            runner.policy_dir = Path(tmpdir)
            customs = runner.get_custom_policies()
            assert customs == []

    def test_results_to_findings(self):
        from vulnpilot.cloud.custodian_runner import CustodianRunner
        runner = CustodianRunner()
        policy = {"name": "test-policy", "description": "Test", "resource": "aws.ec2"}
        resources = [{"InstanceId": "i-12345", "Region": "us-east-1"}]
        findings = runner.results_to_findings("test-policy", policy, resources)
        assert len(findings) == 1
        assert findings[0].check_id == "custodian-test-policy"
        assert findings[0].status == "FAIL"
        assert findings[0].resource_id == "i-12345"


# ═══════════════════════════════════════
# CloudAsset Tests
# ═══════════════════════════════════════

class TestCloudAsset:
    """Test CloudAsset and tier derivation."""

    def test_tier_from_production_tag(self):
        from vulnpilot.cloud.asset_collectors import AWSCollector
        assert AWSCollector._derive_tier({"Environment": "production"}) == "tier_1"
        assert AWSCollector._derive_tier({"Env": "prod"}) == "tier_1"
        assert AWSCollector._derive_tier({"Environment": "staging"}) == "tier_2"
        assert AWSCollector._derive_tier({"Environment": "dev"}) == "tier_3"

    def test_tier_from_explicit_tag(self):
        from vulnpilot.cloud.asset_collectors import AWSCollector
        assert AWSCollector._derive_tier({"AssetTier": "tier_1"}) == "tier_1"
        assert AWSCollector._derive_tier({"Tier": "critical"}) == "tier_1"
        assert AWSCollector._derive_tier({"tier": "high"}) == "tier_2"

    def test_tier_default(self):
        from vulnpilot.cloud.asset_collectors import AWSCollector
        assert AWSCollector._derive_tier({}) == "tier_3"
        assert AWSCollector._derive_tier({}, default="tier_1") == "tier_1"
