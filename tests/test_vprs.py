"""
VulnPilot AI - Test Suite
Run: cd vulnpilot-ai && pytest tests/ -v -s
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from vulnpilot.scoring.vprs import VPRSEngine
from vulnpilot.scoring.hard_rules import HardRulesEngine
from vulnpilot.scanners.base import NormalizedVuln
from vulnpilot.threatintel.base import ThreatIntelResult


@pytest.fixture
def vprs_engine():
    return VPRSEngine("./config/vprs_weights.yaml")

@pytest.fixture
def hard_rules():
    return HardRulesEngine("./config/hard_rules.yaml")

def make_vuln(**kwargs) -> NormalizedVuln:
    defaults = {"cve_id": "CVE-2024-99999", "source_scanner": "test",
                "cvss_base_score": 7.5, "title": "Test Vuln",
                "hostname": "srv-01", "ip_address": "10.0.0.1",
                "asset_tier": "tier_3", "is_internet_facing": False}
    defaults.update(kwargs)
    return NormalizedVuln(**defaults)

def make_intel(**kwargs) -> ThreatIntelResult:
    defaults = {"cve_id": "CVE-2024-99999", "epss_score": 0.05, "in_kev": False}
    defaults.update(kwargs)
    return ThreatIntelResult(**defaults)


class TestVPRSEngine:
    def test_weights_sum_to_one(self, vprs_engine):
        assert abs(sum(vprs_engine.weights.values()) - 1.0) < 0.01

    def test_score_in_range(self, vprs_engine):
        r = vprs_engine.calculate_vprs(make_vuln(), make_intel())
        assert 0 <= r.vprs_score <= 100

    def test_kev_boosts_score(self, vprs_engine):
        vuln = make_vuln(is_internet_facing=True, asset_tier="tier_2")
        s1 = vprs_engine.calculate_vprs(vuln, make_intel(in_kev=False))
        s2 = vprs_engine.calculate_vprs(vuln, make_intel(in_kev=True))
        assert s2.vprs_score > s1.vprs_score

    def test_epss_scaling(self, vprs_engine):
        assert vprs_engine.score_epss(0.95) > vprs_engine.score_epss(0.05)

    def test_tier1_scores_higher(self, vprs_engine):
        intel = make_intel(epss_score=0.3)
        s1 = vprs_engine.calculate_vprs(make_vuln(asset_tier="tier_1", is_internet_facing=True), intel)
        s3 = vprs_engine.calculate_vprs(make_vuln(asset_tier="tier_3"), intel)
        assert s1.vprs_score > s3.vprs_score

    def test_controls_reduce_risk(self, vprs_engine):
        intel = make_intel(epss_score=0.5, in_kev=True)
        exposed = vprs_engine.calculate_vprs(make_vuln(), intel)
        protected = vprs_engine.calculate_vprs(
            make_vuln(has_waf=True, has_ips=True, is_segmented=True), intel)
        assert exposed.vprs_score > protected.vprs_score

    def test_severity_mapping(self, vprs_engine):
        assert vprs_engine._score_to_severity(90) == "critical"
        assert vprs_engine._score_to_severity(70) == "high"
        assert vprs_engine._score_to_severity(50) == "medium"
        assert vprs_engine._score_to_severity(20) == "low"
        assert vprs_engine._score_to_severity(5) == "info"

    def test_the_money_shot_cvss_vs_vprs(self, vprs_engine):
        """THE KEY DEMO: CVSS 9.1 → LOW vs CVSS 7.5 → CRITICAL"""
        noise = vprs_engine.calculate_vprs(
            make_vuln(cve_id="HIGH-CVSS", cvss_base_score=9.1, asset_tier="tier_3",
                      has_waf=True, has_ips=True, is_segmented=True),
            make_intel(cve_id="HIGH-CVSS", epss_score=0.002))

        real = vprs_engine.calculate_vprs(
            make_vuln(cve_id="MOD-CVSS", cvss_base_score=7.5, asset_tier="tier_1",
                      is_internet_facing=True),
            make_intel(cve_id="MOD-CVSS", epss_score=0.85, in_kev=True,
                       ransomware_associated=True, exploit_for_sale=True))

        print(f"\n{'='*60}")
        print(f"  CVSS 9.1 → VPRS {noise.vprs_score} ({noise.severity.upper()})")
        print(f"  CVSS 7.5 → VPRS {real.vprs_score} ({real.severity.upper()})")
        print(f"{'='*60}")

        assert noise.severity in ("low", "info")
        assert real.severity == "critical"
        assert real.vprs_score > noise.vprs_score


class TestHardRules:
    def test_kev_always_critical(self, vprs_engine, hard_rules):
        vuln = make_vuln(asset_tier="tier_3")
        intel = make_intel(epss_score=0.001, in_kev=True)
        vprs = vprs_engine.calculate_vprs(vuln, intel)
        result, rule = hard_rules.evaluate(vuln, intel, vprs)
        assert rule is not None
        assert result.severity == "critical"
        assert result.vprs_score >= 90

    def test_ransomware_critical(self, vprs_engine, hard_rules):
        vuln = make_vuln()
        intel = make_intel(ransomware_associated=True)
        vprs = vprs_engine.calculate_vprs(vuln, intel)
        result, rule = hard_rules.evaluate(vuln, intel, vprs)
        assert result.severity == "critical"


class TestLocalThreatIntel:
    @pytest.mark.asyncio
    async def test_epss_lookup(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/epss_scores.csv"
        p.kev_json_path = "./data/known_exploited_vulns.json"
        assert await p.get_epss("CVE-2024-21887") > 0.9

    @pytest.mark.asyncio
    async def test_kev_lookup(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/epss_scores.csv"
        p.kev_json_path = "./data/known_exploited_vulns.json"
        assert await p.is_in_kev("CVE-2024-21887") is True
        assert await p.is_in_kev("CVE-2024-99999") is False

    @pytest.mark.asyncio
    async def test_full_enrich(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/epss_scores.csv"
        p.kev_json_path = "./data/known_exploited_vulns.json"
        r = await p.enrich("CVE-2024-3400")
        assert r.epss_score > 0.9
        assert r.in_kev is True
        assert r.ransomware_associated is True


class TestConsoleTickets:
    @pytest.mark.asyncio
    async def test_create_ticket(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        result = await p.create_ticket(
            cve_id="CVE-2024-21887", title="[CRITICAL] Ivanti RCE",
            description="Test", priority="P1", assigned_to="security-team",
            sla_hours=24, vprs_score=95.0, justification="Test justification",
            remediation_steps=["Patch Ivanti", "Verify fix"])
        assert result.success
        assert result.ticket_id.startswith("VPAI-")

    @pytest.mark.asyncio
    async def test_sla_check(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        t = await p.create_ticket(
            cve_id="CVE-TEST", title="Test", description="Test",
            priority="P2", assigned_to="test", sla_hours=72,
            vprs_score=70.0, justification="Test", remediation_steps=["Fix"])
        sla = await p.check_sla(t.ticket_id)
        assert sla.status.value == "on_track"
