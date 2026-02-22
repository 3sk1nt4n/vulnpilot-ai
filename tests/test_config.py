"""
VulnPilot AI - Config & Settings Tests
Tests: config.py, api/schemas.py, llm/base.py, llm/prompts.py, models.py enums, factory modules
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from unittest.mock import patch

try:
    import pydantic_settings  # noqa: F401
    HAS_PYDANTIC_SETTINGS = True
except ImportError:
    HAS_PYDANTIC_SETTINGS = False

try:
    import sqlalchemy  # noqa: F401
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

try:
    import httpx  # noqa: F401
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

skip_no_pydantic = pytest.mark.skipif(not HAS_PYDANTIC_SETTINGS, reason="pydantic_settings not installed")
skip_no_sqlalchemy = pytest.mark.skipif(not HAS_SQLALCHEMY, reason="sqlalchemy not installed")
skip_no_httpx = pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed (required for LLM providers)")


# ═══════════════════════════════════════
# config.py - Settings
# ═══════════════════════════════════════

@skip_no_pydantic
class TestSettings:
    def test_default_settings(self):
        from vulnpilot.config import Settings
        with patch.dict(os.environ, {}, clear=True):
            s = Settings()
            assert s.app_name == "VulnPilot AI"
            assert s.llm_provider == "ollama"
            assert s.ticket_provider == "console"
            assert s.threatintel_mode == "local"

    def test_scanner_provider_list(self):
        from vulnpilot.config import Settings
        with patch.dict(os.environ, {"SCANNER_PROVIDERS": "tenable,qualys,rapid7"}, clear=True):
            s = Settings()
            assert s.scanner_provider_list == ["tenable", "qualys", "rapid7"]

    def test_scanner_provider_list_single(self):
        from vulnpilot.config import Settings
        with patch.dict(os.environ, {"SCANNER_PROVIDERS": "openvas"}, clear=True):
            s = Settings()
            assert s.scanner_provider_list == ["openvas"]

    def test_is_local_mode(self):
        from vulnpilot.config import Settings
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}, clear=True):
            s = Settings()
            assert s.is_local_mode is True
            assert s.is_cloud_mode is False

    def test_is_cloud_mode(self):
        from vulnpilot.config import Settings
        with patch.dict(os.environ, {"LLM_PROVIDER": "anthropic"}, clear=True):
            s = Settings()
            assert s.is_cloud_mode is True
            assert s.is_local_mode is False

    def test_get_settings_cached(self):
        from vulnpilot.config import get_settings
        get_settings.cache_clear()
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2
        get_settings.cache_clear()


# ═══════════════════════════════════════
# api/schemas.py - Pydantic models
# ═══════════════════════════════════════

@skip_no_pydantic
class TestSchemas:
    def test_health_response(self):
        from vulnpilot.api.schemas import HealthResponse
        r = HealthResponse(
            llm_provider="ollama", scanner_providers=["openvas"],
            ticket_provider="console", threatintel_mode="local", mode="local"
        )
        assert r.status == "ok"
        assert r.version == "0.1.0"

    def test_provider_status(self):
        from vulnpilot.api.schemas import ProviderStatus
        p = ProviderStatus(name="ollama", healthy=True)
        assert p.error is None
        p2 = ProviderStatus(name="tenable", healthy=False, error="Connection refused")
        assert p2.error == "Connection refused"

    def test_system_status(self):
        from vulnpilot.api.schemas import SystemStatus, ProviderStatus
        ss = SystemStatus(
            llm=ProviderStatus(name="ollama", healthy=True),
            scanners=[ProviderStatus(name="openvas", healthy=True)],
            ticket=ProviderStatus(name="console", healthy=True),
            threatintel=ProviderStatus(name="local", healthy=True),
            database=ProviderStatus(name="postgres", healthy=True),
        )
        assert ss.llm.healthy is True

    def test_vprs_score_response(self):
        from vulnpilot.api.schemas import VPRSScoreResponse, VPRSComponentsResponse
        r = VPRSScoreResponse(
            cve_id="CVE-2024-21887", vprs_score=95.2, severity="critical",
            components=VPRSComponentsResponse(
                epss={"raw": 0.96}, kev={"match": True},
                dark_web={"score": 80}, asset={"score": 100},
                reachability={"score": 100}, controls={"score": 15}
            ),
            weights_used={"epss": 0.25}, sla_hours=24, priority="P1",
        )
        assert r.vprs_score == 95.2

    def test_vulnerability_input_valid(self):
        from vulnpilot.api.schemas import VulnerabilityInput
        v = VulnerabilityInput(cve_id="CVE-2024-21887", cvss_base_score=9.1)
        assert v.asset_tier == "tier_3"

    def test_vulnerability_input_invalid_cve(self):
        from vulnpilot.api.schemas import VulnerabilityInput
        with pytest.raises(Exception):
            VulnerabilityInput(cve_id="not-a-cve")

    def test_vulnerability_input_invalid_tier(self):
        from vulnpilot.api.schemas import VulnerabilityInput
        with pytest.raises(Exception):
            VulnerabilityInput(cve_id="CVE-2024-1234", asset_tier="tier_9")

    def test_vulnerability_input_cvss_range(self):
        from vulnpilot.api.schemas import VulnerabilityInput
        with pytest.raises(Exception):
            VulnerabilityInput(cve_id="CVE-2024-1234", cvss_base_score=11.0)

    def test_batch_score_request(self):
        from vulnpilot.api.schemas import BatchScoreRequest, VulnerabilityInput
        req = BatchScoreRequest(vulnerabilities=[
            VulnerabilityInput(cve_id="CVE-2024-1234"),
            VulnerabilityInput(cve_id="CVE-2024-5678"),
        ])
        assert len(req.vulnerabilities) == 2

    def test_pipeline_result_response(self):
        from vulnpilot.api.schemas import PipelineResultResponse
        r = PipelineResultResponse(
            cve_id="CVE-2024-1234", vprs_score=85.0, severity="critical",
            epss_score=0.85, in_kev=True, hard_rule_triggered=True,
            debate_applied=False, ticket_created=True, ticket_id="VPAI-123",
            processing_time_ms=450.5,
        )
        assert r.ticket_id == "VPAI-123"

    def test_batch_result_response(self):
        from vulnpilot.api.schemas import BatchResultResponse, PipelineResultResponse
        r = BatchResultResponse(
            total_input=10, noise_eliminated=7, noise_elimination_rate=0.7,
            tickets_created=3, critical_count=1, high_count=2,
            medium_count=0, low_count=0, info_count=0,
            hard_rules_triggered=1, adversarial_overrides=0,
            processing_time_seconds=2.5, results=[],
        )
        assert r.noise_elimination_rate == 0.7

    def test_weights_response(self):
        from vulnpilot.api.schemas import WeightsResponse
        w = WeightsResponse(
            epss=0.25, kev=0.20, dark_web=0.15,
            asset_criticality=0.20, reachability=0.12, controls=0.08,
        )
        assert abs(w.epss + w.kev + w.dark_web + w.asset_criticality + w.reachability + w.controls - 1.0) < 0.01

    def test_weights_update_request_valid(self):
        from vulnpilot.api.schemas import WeightsUpdateRequest
        w = WeightsUpdateRequest(
            epss=0.25, kev=0.20, dark_web=0.15,
            asset_criticality=0.20, reachability=0.12, controls=0.08,
        )
        assert w.epss == 0.25

    def test_weights_update_request_invalid(self):
        from vulnpilot.api.schemas import WeightsUpdateRequest
        with pytest.raises(Exception):
            WeightsUpdateRequest(
                epss=1.5, kev=0.20, dark_web=0.15,
                asset_criticality=0.20, reachability=0.12, controls=0.08,
            )


# ═══════════════════════════════════════
# llm/prompts.py - Prompt constants
# ═══════════════════════════════════════

class TestPrompts:
    def test_all_prompts_exist(self):
        from vulnpilot.llm import prompts
        assert len(prompts.CORRELATOR_SYSTEM) > 100
        assert len(prompts.CORRELATOR_PROMPT) > 50
        assert len(prompts.CONTEXT_MAPPER_SYSTEM) > 100
        assert len(prompts.CONTEXT_MAPPER_PROMPT) > 50
        assert len(prompts.JUSTIFIER_SYSTEM) > 100
        assert len(prompts.JUSTIFIER_PROMPT) > 50
        assert len(prompts.CHALLENGER_SYSTEM) > 100
        assert len(prompts.CHALLENGER_PROMPT) > 50
        assert len(prompts.ORCHESTRATOR_SYSTEM) > 100
        assert len(prompts.ORCHESTRATOR_PROMPT) > 50
        assert len(prompts.DEBATE_RESOLUTION_PROMPT) > 50

    def test_prompts_have_placeholders(self):
        from vulnpilot.llm import prompts
        assert "{cve_data}" in prompts.CORRELATOR_PROMPT
        assert "{cve_data}" in prompts.CONTEXT_MAPPER_PROMPT
        assert "{cve_data}" in prompts.JUSTIFIER_PROMPT
        assert "{cve_data}" in prompts.CHALLENGER_PROMPT
        assert "{justifier_argument}" in prompts.CHALLENGER_PROMPT
        assert "{vprs_score}" in prompts.ORCHESTRATOR_PROMPT
        assert "{cve_id}" in prompts.DEBATE_RESOLUTION_PROMPT


# ═══════════════════════════════════════
# llm/base.py - Dataclasses
# ═══════════════════════════════════════

class TestLLMBase:
    def test_debate_result(self):
        from vulnpilot.llm.base import DebateResult
        r = DebateResult(
            justifier_score=85.0, challenger_score=92.0,
            final_score=92.0, justifier_reasoning="Lower risk",
            challenger_reasoning="Higher risk", consensus=False,
            override_applied=True,
        )
        assert r.final_score == 92.0
        assert r.consensus is False

    def test_justification_result(self):
        from vulnpilot.llm.base import JustificationResult
        r = JustificationResult(
            summary="Critical vulnerability", detailed="Full details...",
            board_ready="Executive summary", remediation_steps="Patch now",
        )
        assert "Critical" in r.summary


# ═══════════════════════════════════════
# models.py - Enums
# ═══════════════════════════════════════

@skip_no_sqlalchemy
class TestModelEnums:
    def test_vprs_severity(self):
        from vulnpilot.models import VPRSSeverity
        assert VPRSSeverity.CRITICAL.value == "critical"
        assert VPRSSeverity.HIGH.value == "high"
        assert VPRSSeverity.MEDIUM.value == "medium"
        assert VPRSSeverity.LOW.value == "low"
        assert VPRSSeverity.INFO.value == "info"

    def test_ticket_status(self):
        from vulnpilot.models import TicketStatus
        assert TicketStatus.OPEN.value == "open"
        assert TicketStatus.IN_PROGRESS.value == "in_progress"
        assert TicketStatus.RESOLVED.value == "resolved"
        assert TicketStatus.CLOSED.value == "closed"
        assert TicketStatus.ESCALATED.value == "escalated"

    def test_sla_status(self):
        from vulnpilot.models import SLAStatus
        assert SLAStatus.ON_TRACK.value == "on_track"
        assert SLAStatus.BREACHED.value == "breached"

    def test_asset_tier(self):
        from vulnpilot.models import AssetTier
        assert AssetTier.TIER_1.value == "tier_1"
        assert AssetTier.TIER_2.value == "tier_2"
        assert AssetTier.TIER_3.value == "tier_3"

    def test_orm_models_importable(self):
        from vulnpilot.models import (
            Vulnerability, Asset, VPRSScore, Ticket,
            AuditLog, DriftEvent, CloudFinding,
        )
        assert Vulnerability.__tablename__ == "vulnerabilities"
        assert Asset.__tablename__ == "assets"
        assert VPRSScore.__tablename__ == "vprs_scores"
        assert Ticket.__tablename__ == "tickets"
        assert AuditLog.__tablename__ == "audit_log"
        assert DriftEvent.__tablename__ == "drift_events"
        assert CloudFinding.__tablename__ == "cloud_findings"


# ═══════════════════════════════════════
# Factory modules
# ═══════════════════════════════════════

class TestTicketFactory:
    def test_console_provider(self):
        from vulnpilot.tickets.factory import get_ticket_provider
        get_ticket_provider.cache_clear()
        with patch.dict(os.environ, {"TICKET_PROVIDER": "console"}):
            p = get_ticket_provider()
            assert p.provider_name == "console"
        get_ticket_provider.cache_clear()

    def test_unknown_provider_raises(self):
        from vulnpilot.tickets.factory import get_ticket_provider
        get_ticket_provider.cache_clear()
        with patch.dict(os.environ, {"TICKET_PROVIDER": "unknown_provider"}):
            with pytest.raises(ValueError, match="Unknown TICKET_PROVIDER"):
                get_ticket_provider()
        get_ticket_provider.cache_clear()


class TestThreatIntelFactory:
    def test_local_provider(self):
        from vulnpilot.threatintel.factory import get_threatintel_provider
        get_threatintel_provider.cache_clear()
        with patch.dict(os.environ, {"THREATINTEL_MODE": "local"}):
            p = get_threatintel_provider()
            assert p.provider_name == "local"
        get_threatintel_provider.cache_clear()

    def test_unknown_mode_raises(self):
        from vulnpilot.threatintel.factory import get_threatintel_provider
        get_threatintel_provider.cache_clear()
        with patch.dict(os.environ, {"THREATINTEL_MODE": "invalid"}):
            with pytest.raises(ValueError, match="Unknown THREATINTEL_MODE"):
                get_threatintel_provider()
        get_threatintel_provider.cache_clear()


class TestCMDBFactory:
    def test_csv_provider(self):
        from vulnpilot.cmdb.factory import get_cmdb_provider
        get_cmdb_provider.cache_clear()
        with patch.dict(os.environ, {"CMDB_PROVIDER": "csv"}):
            p = get_cmdb_provider()
            assert hasattr(p, 'provider_name')
        get_cmdb_provider.cache_clear()

    def test_unknown_provider_raises(self):
        from vulnpilot.cmdb.factory import get_cmdb_provider
        get_cmdb_provider.cache_clear()
        with patch.dict(os.environ, {"CMDB_PROVIDER": "invalid"}):
            with pytest.raises(ValueError, match="Unknown CMDB_PROVIDER"):
                get_cmdb_provider()
        get_cmdb_provider.cache_clear()


class TestScannerFactory:
    def test_cloud_provider(self):
        from vulnpilot.scanners.factory import get_scanner_providers
        with patch.dict(os.environ, {"SCANNER_PROVIDERS": "cloud"}):
            providers = get_scanner_providers()
            assert len(providers) == 1
            assert providers[0].provider_name == "cloud"

    def test_unknown_provider_skipped(self):
        from vulnpilot.scanners.factory import get_scanner_providers
        with patch.dict(os.environ, {"SCANNER_PROVIDERS": "nonexistent_scanner"}):
            providers = get_scanner_providers()
            assert len(providers) == 0

    def test_import_class(self):
        from vulnpilot.scanners.factory import _import_class
        cls = _import_class("vulnpilot.tickets.console.ConsoleProvider")
        assert cls.__name__ == "ConsoleProvider"

    def test_multiple_providers(self):
        from vulnpilot.scanners.factory import get_scanner_providers
        with patch.dict(os.environ, {"SCANNER_PROVIDERS": "cloud,cloud"}):
            providers = get_scanner_providers()
            assert len(providers) == 2


# ═══════════════════════════════════════
# tickets/base.py - Dataclasses
# ═══════════════════════════════════════

@skip_no_httpx
class TestLLMFactory:
    def setup_method(self):
        from vulnpilot.llm import factory
        factory._provider_cache.clear()

    def test_get_all_provider_names(self):
        from vulnpilot.llm.factory import get_all_provider_names
        names = get_all_provider_names()
        assert "ollama" in names
        assert "anthropic" in names
        assert "openai" in names

    def test_create_provider_ollama(self):
        from vulnpilot.llm.factory import _create_provider
        p = _create_provider("ollama")
        assert p.provider_name == "ollama"

    def test_create_provider_unknown_raises(self):
        from vulnpilot.llm.factory import _create_provider
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            _create_provider("gemini")

    def test_get_llm_provider_default(self):
        from vulnpilot.llm.factory import get_llm_provider
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}):
            p = get_llm_provider()
            assert p.provider_name == "ollama"

    def test_get_provider_by_name_caching(self):
        from vulnpilot.llm.factory import get_provider_by_name
        p1 = get_provider_by_name("ollama")
        p2 = get_provider_by_name("ollama")
        assert p1 is p2

    def test_get_provider_by_name_alias_claude(self):
        from vulnpilot.llm.factory import get_provider_by_name
        p = get_provider_by_name("claude")
        assert p.provider_name == "anthropic"

    def test_get_provider_by_name_none_uses_env(self):
        from vulnpilot.llm.factory import get_provider_by_name
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}):
            p = get_provider_by_name(None)
            assert p.provider_name == "ollama"

    def test_get_challenger_provider_empty(self):
        from vulnpilot.llm.factory import get_challenger_provider
        with patch.dict(os.environ, {"CHALLENGER_PROVIDER": ""}):
            assert get_challenger_provider() is None

    def test_get_challenger_provider_set(self):
        from vulnpilot.llm.factory import get_challenger_provider
        with patch.dict(os.environ, {"CHALLENGER_PROVIDER": "ollama"}):
            p = get_challenger_provider()
            assert p.provider_name == "ollama"

    @pytest.mark.asyncio
    async def test_get_provider_health(self):
        from vulnpilot.llm.factory import get_provider_health
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}, clear=True):
            results = await get_provider_health()
            assert "ollama" in results
            assert "anthropic" in results
            assert "openai" in results
            assert results["anthropic"]["reason"] == "no_key"
            assert results["openai"]["reason"] == "no_key"


class TestCMDBProvider:
    @pytest.mark.asyncio
    async def test_csv_provider_not_found(self):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        p = CSVCMDBProvider()
        p.file_path = "/nonexistent/cmdb.csv"
        result = await p.lookup_by_ip("10.0.0.1")
        assert result is None

    @pytest.mark.asyncio
    async def test_csv_provider_load_csv(self, tmp_path):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        csv_file = tmp_path / "cmdb.csv"
        csv_file.write_text(
            "hostname,ip_address,asset_tier,business_unit,owner,owner_email,"
            "is_internet_facing,network_zone,has_waf,has_ips,is_segmented,environment\n"
            "web-01,10.0.0.1,tier_1,payments,security-team,sec@co.com,"
            "true,dmz,true,true,false,production\n"
            "db-01,10.0.0.2,tier_2,backend,db-team,db@co.com,"
            "false,internal,false,false,true,production\n"
        )
        p = CSVCMDBProvider()
        p.file_path = str(csv_file)
        result = await p.lookup_by_ip("10.0.0.1")
        assert result is not None
        assert result.hostname == "web-01"
        assert result.asset_tier == "tier_1"
        assert result.is_internet_facing is True
        assert result.has_waf is True

    @pytest.mark.asyncio
    async def test_csv_provider_load_json(self, tmp_path):
        import json
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        json_file = tmp_path / "cmdb.json"
        json_file.write_text(json.dumps([
            {"hostname": "api-01", "ip_address": "10.0.1.1", "asset_tier": "tier_1",
             "is_internet_facing": True, "has_waf": True, "owner": "api-team"},
        ]))
        p = CSVCMDBProvider()
        p.file_path = str(json_file)
        result = await p.lookup_by_hostname("api-01")
        assert result is not None
        assert result.asset_tier == "tier_1"
        assert result.is_internet_facing is True

    @pytest.mark.asyncio
    async def test_csv_provider_json_dict_format(self, tmp_path):
        import json
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        json_file = tmp_path / "cmdb.json"
        json_file.write_text(json.dumps({"assets": [
            {"hostname": "srv-01", "ip_address": "10.0.2.1"},
        ]}))
        p = CSVCMDBProvider()
        p.file_path = str(json_file)
        result = await p.lookup_by_ip("10.0.2.1")
        assert result is not None

    @pytest.mark.asyncio
    async def test_csv_provider_get_all(self, tmp_path):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        csv_file = tmp_path / "cmdb.csv"
        csv_file.write_text(
            "hostname,ip_address,asset_tier\n"
            "web-01,10.0.0.1,tier_1\n"
            "db-01,10.0.0.2,tier_2\n"
        )
        p = CSVCMDBProvider()
        p.file_path = str(csv_file)
        assets = await p.get_all_assets()
        assert len(assets) == 2

    @pytest.mark.asyncio
    async def test_csv_provider_health_check(self, tmp_path):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        csv_file = tmp_path / "cmdb.csv"
        csv_file.write_text("hostname,ip_address\n")
        p = CSVCMDBProvider()
        p.file_path = str(csv_file)
        assert await p.health_check() is True
        p.file_path = "/nonexistent"
        assert await p.health_check() is False

    def test_csv_provider_name(self):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        assert CSVCMDBProvider().provider_name == "csv"

    @pytest.mark.asyncio
    async def test_enrich_vuln_by_hostname(self, tmp_path):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        csv_file = tmp_path / "cmdb.csv"
        csv_file.write_text("hostname,ip_address,asset_tier\nweb-01,10.0.0.1,tier_1\n")
        p = CSVCMDBProvider()
        p.file_path = str(csv_file)
        result = await p.enrich_vuln("web-01", "")
        assert result is not None
        assert result.asset_tier == "tier_1"

    @pytest.mark.asyncio
    async def test_enrich_vuln_by_ip(self, tmp_path):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        csv_file = tmp_path / "cmdb.csv"
        csv_file.write_text("hostname,ip_address,asset_tier\nweb-01,10.0.0.1,tier_1\n")
        p = CSVCMDBProvider()
        p.file_path = str(csv_file)
        result = await p.enrich_vuln("", "10.0.0.1")
        assert result is not None

    @pytest.mark.asyncio
    async def test_enrich_vuln_no_match(self):
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        p = CSVCMDBProvider()
        p.file_path = "/nonexistent"
        result = await p.enrich_vuln("", "")
        assert result is None

    def test_asset_record_defaults(self):
        from vulnpilot.cmdb.provider import AssetRecord
        r = AssetRecord()
        assert r.hostname == ""
        assert r.asset_tier == "tier_3"
        assert r.is_internet_facing is False
        assert r.tags == []

    def test_servicenow_provider_name(self):
        from vulnpilot.cmdb.provider import ServiceNowCMDBProvider
        p = ServiceNowCMDBProvider()
        assert p.provider_name == "servicenow_cmdb"


class TestTicketBase:
    def test_sla_status_enum(self):
        from vulnpilot.tickets.base import SLAStatusEnum
        assert SLAStatusEnum.ON_TRACK.value == "on_track"
        assert SLAStatusEnum.BREACHED.value == "breached"

    def test_ticket_result(self):
        from vulnpilot.tickets.base import TicketResult
        from datetime import datetime, timedelta
        deadline = datetime.utcnow() + timedelta(hours=24)
        r = TicketResult(
            ticket_id="VPAI-ABC123",
            ticket_url="console://VPAI-ABC123",
            provider="console",
            assigned_to="security-team",
            sla_deadline=deadline,
            sla_hours=24,
        )
        assert r.success is True
        assert r.ticket_id == "VPAI-ABC123"

    def test_sla_check_result(self):
        from vulnpilot.tickets.base import SLACheckResult, SLAStatusEnum
        r = SLACheckResult(
            ticket_id="VPAI-ABC123",
            status=SLAStatusEnum.WARNING,
            hours_remaining=6.0,
            percent_elapsed=75.0,
            needs_nudge=True,
            needs_escalation=True,
            current_ticket_status="open",
        )
        assert r.needs_escalation is True
