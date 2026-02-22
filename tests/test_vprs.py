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

    @pytest.mark.asyncio
    async def test_uses_bundled_fallback_when_files_missing(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/does-not-exist-epss.csv"
        p.kev_json_path = "./data/does-not-exist-kev.json"

        r = await p.enrich("CVE-2024-3400")
        assert r.epss_score > 0.9
        assert r.in_kev is True
        assert "epss_fallback" in r.sources
        assert "kev_fallback" in r.sources

    @pytest.mark.asyncio
    async def test_fallback_when_primary_files_are_invalid(self, tmp_path):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider

        bad_epss = tmp_path / "bad_epss.csv"
        bad_kev = tmp_path / "bad_kev.json"
        bad_epss.write_text("cve,epss,percentile\nCVE-2024-3400,not-a-number,0.995\n")
        bad_kev.write_text("{ invalid json }")

        p = LocalThreatIntelProvider()
        p.epss_csv_path = str(bad_epss)
        p.kev_json_path = str(bad_kev)

        r = await p.enrich("CVE-2024-3400")
        assert r.epss_score > 0.9
        assert r.in_kev is True
        assert "epss_fallback" in r.sources
        assert "kev_fallback" in r.sources


class TestNormalizedVulnToDict:
    def test_to_dict(self):
        vuln = make_vuln(title="Test Vuln", description="desc", solution="sol")
        d = vuln.to_dict()
        assert d["cve_id"] == "CVE-2024-99999"
        assert d["asset_tier"] == "tier_3"
        assert "hostname" in d


class TestThreatIntelResultToDict:
    def test_to_dict(self):
        intel = make_intel(epss_score=0.85, in_kev=True)
        d = intel.to_dict()
        assert d["cve_id"] == "CVE-2024-99999"
        assert d["epss_score"] == 0.85
        assert d["in_kev"] is True


class TestLocalThreatIntelExtended:
    @pytest.mark.asyncio
    async def test_get_dark_web_intel(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/epss_scores.csv"
        p.kev_json_path = "./data/known_exploited_vulns.json"
        result = await p.get_dark_web_intel("CVE-2024-21887")
        assert result["exploit_available"] is True
        assert result["dark_web_mentions"] == 0
        assert "note" in result

    @pytest.mark.asyncio
    async def test_get_dark_web_intel_unknown_cve(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/epss_scores.csv"
        p.kev_json_path = "./data/known_exploited_vulns.json"
        result = await p.get_dark_web_intel("CVE-9999-99999")
        assert result["exploit_available"] is False

    @pytest.mark.asyncio
    async def test_refresh_cache(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/epss_scores.csv"
        p.kev_json_path = "./data/known_exploited_vulns.json"
        # Load initially
        await p.enrich("CVE-2024-21887")
        assert p._loaded is True
        # Refresh
        result = await p.refresh_cache()
        assert result is True
        assert p._loaded is True

    @pytest.mark.asyncio
    async def test_health_check(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        p.epss_csv_path = "./data/epss_scores.csv"
        p.kev_json_path = "./data/known_exploited_vulns.json"
        assert await p.health_check() is True

    def test_provider_name(self):
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        p = LocalThreatIntelProvider()
        assert p.provider_name == "local"


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

    @pytest.mark.asyncio
    async def test_sla_check_unknown_ticket(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        sla = await p.check_sla("VPAI-NONEXIST")
        assert sla.status.value == "on_track"
        assert sla.hours_remaining == 0
        assert sla.current_ticket_status == "unknown"

    @pytest.mark.asyncio
    async def test_sla_breached(self):
        from vulnpilot.tickets.console import ConsoleProvider, _ticket_store
        from datetime import datetime, timedelta
        p = ConsoleProvider()
        t = await p.create_ticket(
            cve_id="CVE-SLA", title="Test", description="Test",
            priority="P1", assigned_to="test", sla_hours=1,
            vprs_score=95.0, justification="Test", remediation_steps=["Fix"])
        # Backdate creation to force breach
        _ticket_store[t.ticket_id]["created_at"] = datetime.utcnow() - timedelta(hours=2)
        sla = await p.check_sla(t.ticket_id)
        assert sla.status.value == "breached"
        assert sla.needs_escalation is True

    @pytest.mark.asyncio
    async def test_sla_warning(self):
        from vulnpilot.tickets.console import ConsoleProvider, _ticket_store
        from datetime import datetime, timedelta
        p = ConsoleProvider()
        t = await p.create_ticket(
            cve_id="CVE-SLA-W", title="Test", description="Test",
            priority="P1", assigned_to="test", sla_hours=100,
            vprs_score=80.0, justification="Test", remediation_steps=["Fix"])
        # 80% elapsed → WARNING
        _ticket_store[t.ticket_id]["created_at"] = datetime.utcnow() - timedelta(hours=80)
        sla = await p.check_sla(t.ticket_id)
        assert sla.status.value == "warning"

    @pytest.mark.asyncio
    async def test_sla_at_risk(self):
        from vulnpilot.tickets.console import ConsoleProvider, _ticket_store
        from datetime import datetime, timedelta
        p = ConsoleProvider()
        t = await p.create_ticket(
            cve_id="CVE-SLA-R", title="Test", description="Test",
            priority="P2", assigned_to="test", sla_hours=100,
            vprs_score=75.0, justification="Test", remediation_steps=["Fix"])
        # 60% elapsed → AT_RISK
        _ticket_store[t.ticket_id]["created_at"] = datetime.utcnow() - timedelta(hours=60)
        sla = await p.check_sla(t.ticket_id)
        assert sla.status.value == "at_risk"
        assert sla.needs_nudge is True

    @pytest.mark.asyncio
    async def test_update_ticket(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        t = await p.create_ticket(
            cve_id="CVE-UPD", title="Test", description="Test",
            priority="P2", assigned_to="test", sla_hours=48,
            vprs_score=70.0, justification="Test", remediation_steps=["Fix"])
        assert await p.update_ticket(t.ticket_id, status="in_progress") is True

    @pytest.mark.asyncio
    async def test_update_ticket_not_found(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        assert await p.update_ticket("VPAI-MISSING", status="closed") is False

    @pytest.mark.asyncio
    async def test_add_comment(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        assert await p.add_comment("VPAI-ANY", "This is a test comment") is True

    @pytest.mark.asyncio
    async def test_health_check(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        assert await p.health_check() is True

    def test_provider_name(self):
        from vulnpilot.tickets.console import ConsoleProvider
        p = ConsoleProvider()
        assert p.provider_name == "console"


class TestHardRulesExtended:
    """Cover uncovered branches in hard_rules.py."""

    def test_file_not_found(self):
        engine = HardRulesEngine("/nonexistent/path/rules.yaml")
        assert engine.rules == []

    def test_no_rule_matched(self, vprs_engine, hard_rules):
        """No rules fire → returns (result, None)."""
        vuln = make_vuln(asset_tier="tier_3", is_internet_facing=True)
        intel = make_intel(epss_score=0.5, in_kev=False)
        vprs = vprs_engine.calculate_vprs(vuln, intel)
        result, match = hard_rules.evaluate(vuln, intel, vprs)
        # Rule 6 (no_signals_floor) needs epss<0.01 + no KEV + no DW + not internet-facing
        # This vuln has epss=0.5 + internet-facing, so no rule should match except maybe #3
        # Rule 3 needs epss>0.7 AND internet-facing → 0.5 fails, so no match
        assert match is None

    def test_unknown_field(self, vprs_engine, hard_rules):
        """Rule referencing unknown field logs warning and returns False."""
        vuln = make_vuln()
        intel = make_intel()
        cond = {"field": "nonexistent_field", "operator": "equals", "value": True}
        assert hard_rules._evaluate_condition(cond, vuln, intel) is False

    def test_operator_greater_than(self, hard_rules):
        vuln = make_vuln(cvss_base_score=9.0)
        intel = make_intel()
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "greater_than", "value": 8.0}, vuln, intel
        ) is True
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "greater_than", "value": 9.5}, vuln, intel
        ) is False

    def test_operator_less_than(self, hard_rules):
        vuln = make_vuln(cvss_base_score=3.0)
        intel = make_intel()
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "less_than", "value": 5.0}, vuln, intel
        ) is True
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "less_than", "value": 2.0}, vuln, intel
        ) is False

    def test_operator_greater_equal(self, hard_rules):
        vuln = make_vuln(cvss_base_score=7.5)
        intel = make_intel()
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "greater_equal", "value": 7.5}, vuln, intel
        ) is True
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "greater_equal", "value": 8.0}, vuln, intel
        ) is False

    def test_operator_less_equal(self, hard_rules):
        vuln = make_vuln(cvss_base_score=5.0)
        intel = make_intel()
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "less_equal", "value": 5.0}, vuln, intel
        ) is True
        assert hard_rules._evaluate_condition(
            {"field": "cvss_base_score", "operator": "less_equal", "value": 4.0}, vuln, intel
        ) is False

    def test_operator_not_equals(self, hard_rules):
        vuln = make_vuln()
        intel = make_intel(in_kev=False)
        assert hard_rules._evaluate_condition(
            {"field": "in_kev", "operator": "not_equals", "value": True}, vuln, intel
        ) is True
        assert hard_rules._evaluate_condition(
            {"field": "in_kev", "operator": "not_equals", "value": False}, vuln, intel
        ) is False

    def test_unknown_operator(self, hard_rules):
        vuln = make_vuln()
        intel = make_intel()
        assert hard_rules._evaluate_condition(
            {"field": "in_kev", "operator": "BETWEEN", "value": True}, vuln, intel
        ) is False

    def test_multi_condition_and(self, vprs_engine, hard_rules):
        """Rule 3: EPSS > 0.7 AND internet-facing → critical."""
        vuln = make_vuln(is_internet_facing=True, asset_tier="tier_2")
        intel = make_intel(epss_score=0.85, in_kev=False)
        vprs = vprs_engine.calculate_vprs(vuln, intel)
        result, match = hard_rules.evaluate(vuln, intel, vprs)
        assert match is not None
        assert match.rule_name == "high_epss_internet_facing"
        assert result.severity == "critical"

    def test_multi_condition_and_fails(self, vprs_engine, hard_rules):
        """EPSS > 0.7 but NOT internet-facing → rule 3 skipped."""
        vuln = make_vuln(is_internet_facing=False, asset_tier="tier_3")
        intel = make_intel(epss_score=0.85, in_kev=False)
        vprs = vprs_engine.calculate_vprs(vuln, intel)
        result, match = hard_rules.evaluate(vuln, intel, vprs)
        # No match because AND requires both conditions
        assert match is None

    def test_no_signals_floor_maximum_vprs(self, vprs_engine, hard_rules):
        """Rule 6 (no_signals_floor): maximum_vprs cap at 20."""
        vuln = make_vuln(
            cvss_base_score=9.0, asset_tier="tier_3",
            is_internet_facing=False,
        )
        intel = make_intel(epss_score=0.005, in_kev=False, dark_web_mentions=0)
        vprs = vprs_engine.calculate_vprs(vuln, intel)
        # Force a higher score to ensure maximum_vprs cap is exercised (line 153)
        vprs.vprs_score = 50.0
        result, match = hard_rules.evaluate(vuln, intel, vprs)
        assert match is not None
        assert match.rule_name == "no_signals_floor"
        assert result.vprs_score == 20

    def test_or_logic_conditions(self, vprs_engine, tmp_path):
        """OR logic: either condition triggers the rule."""
        rules_yaml = tmp_path / "or_rules.yaml"
        rules_yaml.write_text(
            "rules:\n"
            "  - name: or_test\n"
            "    description: test or logic\n"
            "    conditions:\n"
            "      - field: in_kev\n"
            "        operator: equals\n"
            "        value: true\n"
            "      - field: exploit_for_sale\n"
            "        operator: equals\n"
            "        value: true\n"
            "    logic: or\n"
            "    action:\n"
            "      override_severity: critical\n"
            "    priority: 1\n"
        )
        engine = HardRulesEngine(str(rules_yaml))
        vuln = make_vuln()
        # Only exploit_for_sale is True, in_kev is False → OR should match
        intel = make_intel(in_kev=False, exploit_for_sale=True)
        vprs = vprs_engine.calculate_vprs(vuln, intel)
        result, match = engine.evaluate(vuln, intel, vprs)
        assert match is not None
        assert match.rule_name == "or_test"


class TestVPRSEngineExtended:
    """Cover uncovered branches in vprs.py."""

    def test_to_dict(self, vprs_engine):
        vprs = vprs_engine.calculate_vprs(make_vuln(), make_intel())
        d = vprs.to_dict()
        assert "vprs_score" in d
        assert "components" in d
        assert "epss" in d["components"]
        assert "hard_rule_triggered" in d

    def test_file_not_found_defaults(self):
        engine = VPRSEngine("/nonexistent/vprs_weights.yaml")
        assert abs(sum(engine.weights.values()) - 1.0) < 0.01
        assert "critical" in engine.thresholds

    def test_invalid_weights_raises(self, tmp_path):
        bad_config = tmp_path / "bad_weights.yaml"
        bad_config.write_text(
            "weights:\n  epss: 0.5\n  kev: 0.5\n  dark_web: 0.5\n"
            "  asset_criticality: 0.0\n  reachability: 0.0\n  controls: 0.0\n"
            "thresholds:\n  critical: 85\n  high: 65\n  medium: 40\n  low: 15\n"
        )
        with pytest.raises(ValueError, match="must sum to 1.0"):
            VPRSEngine(str(bad_config))

    def test_epss_linear_fallback(self):
        """When no thresholds in config, uses linear scaling."""
        engine = VPRSEngine("/nonexistent/vprs_weights.yaml")
        assert engine.score_epss(0.5) == pytest.approx(50.0)
        assert engine.score_epss(1.0) == pytest.approx(100.0)

    def test_score_dark_web_exploit_available(self, vprs_engine):
        intel = make_intel(exploit_available=True)
        score = vprs_engine.score_dark_web(intel)
        assert score > 0

    def test_score_dark_web_active_scanning(self, vprs_engine):
        intel = make_intel(active_scanning=True)
        score = vprs_engine.score_dark_web(intel)
        assert score > 0

    def test_score_dark_web_mentions_high(self, vprs_engine):
        intel = make_intel(dark_web_mentions=5)
        score = vprs_engine.score_dark_web(intel)
        assert score > 0

    def test_score_dark_web_mentions_low(self, vprs_engine):
        intel = make_intel(dark_web_mentions=2)
        score = vprs_engine.score_dark_web(intel)
        assert score > 0

    def test_score_controls_waf_and_ips(self, vprs_engine):
        vuln = make_vuln(has_waf=True, has_ips=True, is_segmented=False)
        score = vprs_engine.score_controls(vuln)
        assert score < 100

    def test_score_controls_waf_only(self, vprs_engine):
        vuln = make_vuln(has_waf=True, has_ips=False, is_segmented=False)
        score = vprs_engine.score_controls(vuln)
        assert score < 100

    def test_score_controls_ips_only(self, vprs_engine):
        vuln = make_vuln(has_waf=False, has_ips=True, is_segmented=False)
        score = vprs_engine.score_controls(vuln)
        assert score < 100

    def test_score_controls_segmented_only(self, vprs_engine):
        vuln = make_vuln(has_waf=False, has_ips=False, is_segmented=True)
        score = vprs_engine.score_controls(vuln)
        assert score < 100
