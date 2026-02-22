# VulnPilot AI - Test Coverage Analysis

## Current State

**Overall line coverage: 12%** (780 of 6,525 statements covered)
**Test files:** 2 pytest files (`test_vprs.py`, `test_cloud.py`) + 2 standalone scripts (`run_tests.py`, `scenario_library.py`)
**All 41 pytest tests pass.**

### Coverage by Module

| Module | Stmts | Covered | % | Notes |
|---|---|---|---|---|
| `scoring/vprs.py` | 134 | 120 | **90%** | Core engine, well tested |
| `scoring/hard_rules.py` | 85 | 59 | **69%** | Missing: EPSS-only rule, tier-1 internet-facing rule, edge cases |
| `scanners/base.py` | 46 | 45 | **98%** | Data model, well tested |
| `threatintel/base.py` | 36 | 35 | **97%** | Data model, well tested |
| `threatintel/local_provider.py` | 103 | 92 | **89%** | Good coverage including fallback paths |
| `cloud/ocsf_parser.py` | 136 | 121 | **89%** | Solid unit tests |
| `cloud/scanner_provider.py` | 73 | 49 | **67%** | Covered via demo mode only |
| `tickets/base.py` | 44 | 44 | **100%** | Full coverage |
| `tickets/console.py` | 48 | 34 | **71%** | Missing: SLA breach/warning paths |
| `cloud/prowler_runner.py` | 107 | 48 | **45%** | Command building tested, execution not |
| `cloud/credentials.py` | 95 | 37 | **39%** | Only no-creds and partial-creds tested |
| `cloud/custodian_runner.py` | 87 | 34 | **39%** | Built-in policies tested, execution not |
| `cloud/asset_collectors.py` | 318 | 60 | **19%** | Only `_derive_tier` tested |

### Modules with 0% Coverage (Completely Untested)

| Module | Stmts | Risk | Description |
|---|---|---|---|
| **`api/routes.py`** | **977** | **CRITICAL** | All REST API endpoints - the entire user-facing interface |
| **`agents/pipeline.py`** | **201** | **CRITICAL** | The core 5-step scoring pipeline |
| **`tasks.py`** | **275** | HIGH | Celery background tasks (drift, SLA, intel refresh) |
| **`reports/generator.py`** | **344** | HIGH | Multi-format report generation (CSV, XLSX, PDF, JSON, MD) |
| **`models.py`** | **183** | HIGH | SQLAlchemy ORM models |
| **`auth/auth.py`** | **85** | HIGH | JWT authentication, password hashing, user store |
| **`auth/middleware.py`** | **30** | HIGH | Role-based access control middleware |
| **`auth/routes.py`** | **56** | HIGH | Login/register/user management endpoints |
| **`guardrails.py`** | **67** | HIGH | Input/output security filtering, jailbreak detection |
| **`drift.py`** | **122** | HIGH | Lock 3 drift detector - score change tracking |
| **`config.py`** | **69** | MEDIUM | Settings / environment configuration |
| **`llm/factory.py`** | **62** | MEDIUM | LLM provider factory and hot-swap logic |
| **`llm/anthropic_provider.py`** | **91** | MEDIUM | Anthropic LLM integration |
| **`llm/ollama_provider.py`** | **102** | MEDIUM | Ollama LLM integration |
| **`llm/openai_provider.py`** | **118** | MEDIUM | OpenAI LLM integration |
| **`llm/base.py`** | **39** | MEDIUM | LLM abstract base class and data models |
| **`llm/prompts.py`** | **11** | LOW | Prompt templates |
| **`scanners/tenable.py`** | **85** | MEDIUM | Tenable.io scanner integration |
| **`scanners/qualys.py`** | **122** | MEDIUM | Qualys scanner integration |
| **`scanners/rapid7.py`** | **97** | MEDIUM | Rapid7 scanner integration |
| **`scanners/openvas.py`** | **96** | MEDIUM | OpenVAS scanner integration |
| **`scanners/wazuh.py`** | **124** | MEDIUM | Wazuh scanner integration |
| **`scanners/nessus_file.py`** | **77** | MEDIUM | Nessus file parser |
| **`scanners/resilience.py`** | **80** | MEDIUM | Rate limiter, circuit breaker, retry logic |
| **`scanners/factory.py`** | **27** | MEDIUM | Scanner factory / registry |
| **`tickets/jira_provider.py`** | **68** | MEDIUM | Jira ticket integration |
| **`tickets/servicenow.py`** | **66** | MEDIUM | ServiceNow ticket integration |
| **`tickets/pagerduty.py`** | **48** | MEDIUM | PagerDuty ticket integration |
| **`tickets/factory.py`** | **21** | MEDIUM | Ticket provider factory |
| **`threatintel/api_provider.py`** | **173** | MEDIUM | OTX/GreyNoise/Shodan API threat intel |
| **`threatintel/darkweb_provider.py`** | **209** | MEDIUM | Dark web signal aggregation |
| **`threatintel/mitre_attack.py`** | **56** | MEDIUM | MITRE ATT&CK mapping (tested in `run_tests.py` but not pytest) |
| **`threatintel/nvd_client.py`** | **113** | MEDIUM | NVD API client |
| **`threatintel/factory.py`** | **13** | LOW | Threat intel factory |
| **`cmdb/provider.py`** | **180** | MEDIUM | CSV CMDB asset lookups (tested in `run_tests.py` but not pytest) |
| **`cmdb/factory.py`** | **13** | LOW | CMDB factory |
| **`demo_seed.py`** | **175** | LOW | Demo data seeder |
| **`live_seed.py`** | **225** | LOW | Live data seeder |
| **`main.py`** | **68** | LOW | FastAPI app entry point |
| **`db/session.py`** | **19** | LOW | Database session management |

---

## Recommended Improvements (Priority Order)

### Priority 1: Guardrails & Security (High Impact, Easy to Test)

**Module:** `guardrails.py` (67 stmts, 0% covered)

This module is critical for security - it blocks jailbreaks, prompt injections, and data exfiltration attempts. It is entirely pure-function logic with no external dependencies, making it trivial to unit test.

**Suggested tests:**
- `scan_input()` with each category of jailbreak pattern (7+ categories)
- `scan_input()` with hard-block patterns (should return `blocked=True`)
- `scan_input()` cumulative risk score reaching 80 triggers block
- `scan_input()` with safe input returns `safe=True`
- `scan_output()` detects credential leakage patterns
- `scan_output()` detects system prompt leakage
- `scan_output()` passes clean output
- `check_escalation()` with educational-to-manipulative conversation progression
- `check_escalation()` with short conversation (< 4 messages) returns None
- `get_guardrail_injection()` returns empty string for safe input
- `get_guardrail_injection()` returns warning injection for unsafe input

### Priority 2: Authentication & Authorization (Security-Critical)

**Modules:** `auth/auth.py` (85 stmts), `auth/middleware.py` (30 stmts), `auth/routes.py` (56 stmts)

Auth is security-critical and entirely testable without external services.

**Suggested tests:**
- `_hash_password()` / `_verify_password()` round-trip
- `_verify_password()` rejects wrong password
- `_create_token()` / `_decode_token()` round-trip (dev fallback mode)
- `_decode_token()` rejects expired tokens
- `_decode_token()` rejects malformed tokens
- `UserStore.authenticate()` with valid and invalid credentials
- `UserStore.create_user()` prevents duplicates, validates roles
- `UserStore.delete_user()` prevents deleting admin
- `require_auth` dependency raises 401 when auth enabled and no token
- `require_role()` raises 403 for unauthorized roles

### Priority 3: API Route Integration Tests (Highest Statement Count)

**Module:** `api/routes.py` (977 stmts, 0% covered)

This is the largest untested module and represents the entire user-facing interface. FastAPI's `TestClient` makes this straightforward.

**Suggested tests:**
- `GET /api/v1/health` returns expected structure
- `GET /api/v1/status` returns provider statuses
- `POST /api/v1/score` with valid vulnerability input
- `POST /api/v1/score` with invalid input returns 422
- `POST /api/v1/batch` scores multiple CVEs
- `GET /api/v1/weights` returns current VPRS weights
- `GET /api/v1/pipeline/results` returns stored results
- Error handling: nonexistent CVE, malformed requests

### Priority 4: Drift Detector (Lock 3)

**Module:** `drift.py` (122 stmts, 0% covered)

The drift detector is a core safety mechanism. It stores score snapshots and detects when threat intelligence changes cause score changes.

**Suggested tests:**
- `_load_store()` / `_save_store()` round-trip with temp files
- Score snapshot creation and storage
- Drift detection when KEV status changes (score should jump)
- Drift detection when EPSS changes significantly
- Tier-based interval configuration
- Drift log recording

### Priority 5: Scanner Normalization (High Volume, Error-Prone)

**Modules:** `scanners/tenable.py`, `scanners/qualys.py`, `scanners/rapid7.py`, `scanners/nessus_file.py`, `scanners/openvas.py`, `scanners/wazuh.py` (total: 681 stmts, 0% covered)

Scanner normalization is where raw data is converted to `NormalizedVuln`. Bugs here silently corrupt all downstream scoring.

**Suggested tests (per scanner):**
- `_normalize()` with well-formed input produces correct `NormalizedVuln`
- `_normalize()` with multi-CVE plugins expands correctly (Tenable-specific)
- `_normalize()` handles missing fields gracefully (doesn't crash)
- `_normalize()` with edge cases: empty CVE list, malformed CVSS, missing hostname
- Factory: `get_scanner_providers()` loads correct providers from env var
- Factory: unknown provider name logs warning and continues

### Priority 6: Report Generator

**Module:** `reports/generator.py` (344 stmts, 0% covered)

Report generation is user-facing and supports multiple formats (CSV, JSON, Markdown, etc.).

**Suggested tests:**
- CSV export produces valid CSV with correct headers
- JSON export round-trips correctly
- Markdown export contains expected sections
- `ReportConfig` validation
- `ReportData` computation from pipeline results
- Empty results produce valid (empty) reports rather than crashes

### Priority 7: Resilience Layer

**Module:** `scanners/resilience.py` (80 stmts, 0% covered)

Rate limiter, circuit breaker, and retry logic are foundational infrastructure.

**Suggested tests:**
- `RateLimiter`: respects max_requests within window
- `CircuitBreaker`: opens after failure threshold
- `CircuitBreaker`: transitions to half-open after cooldown
- `CircuitBreaker`: closes after success in half-open
- `retry_with_backoff`: retries on failure, returns on success

### Priority 8: Pipeline Integration Tests

**Module:** `agents/pipeline.py` (201 stmts, 0% covered)

The pipeline orchestrates the entire scoring flow. Testing it requires mocking LLM and external providers.

**Suggested tests:**
- Pipeline processes a single vulnerability end-to-end (with mocked LLM/intel)
- Pipeline batch processing computes correct summary stats
- Hard rule triggers override pipeline score
- Pipeline handles threat intel enrichment failure gracefully
- Pipeline handles LLM failure gracefully (falls back to score-only)

### Priority 9: Ticket Provider Implementations

**Modules:** `tickets/jira_provider.py`, `tickets/servicenow.py`, `tickets/pagerduty.py` (total: 182 stmts, 0% covered)

These interact with external APIs but can be tested with mocked HTTP responses.

**Suggested tests:**
- Ticket creation constructs correct API payloads
- Priority mapping (P1→Highest, etc.)
- Error handling when API returns errors
- SLA check computation

### Priority 10: LLM Provider Factory & Providers

**Modules:** `llm/factory.py` (62 stmts), `llm/base.py` (39 stmts), providers (311 stmts total, 0% covered)

**Suggested tests:**
- Factory creates correct provider from name
- Factory normalizes aliases ("claude" → "anthropic", "gpt" → "openai")
- Factory caches provider instances
- Factory raises on unknown provider name
- Challenger provider returns None when env var empty

---

## Additional Structural Improvements

### 1. Migrate `run_tests.py` Tests to pytest

`run_tests.py` and `scenario_library.py` contain valuable tests (MITRE ATT&CK, CMDB, weekly report, NVD client, full pipeline demo) that use a custom test runner. These should be migrated to pytest so they run in CI and contribute to coverage metrics. Key tests to migrate:
- MITRE ATT&CK mapping tests → `test_threatintel.py`
- CMDB lookup tests → `test_cmdb.py`
- Weekly report generation tests → `test_reports.py`
- NVD client structure tests → `test_threatintel.py`
- Full pipeline 10-CVE demo → `test_pipeline_integration.py`

### 2. Add `conftest.py` with Shared Fixtures

Create `tests/conftest.py` with reusable fixtures:
- `vprs_engine` and `hard_rules` (already duplicated between test files)
- `make_vuln()` and `make_intel()` helpers (duplicated 3 times)
- `mock_llm_provider` for pipeline/route tests
- `sample_pipeline_result` for report tests
- FastAPI `TestClient` fixture for API tests

### 3. Add pytest Configuration

Add `pytest.ini` or `[tool.pytest.ini_options]` to a `pyproject.toml`:
- Set `asyncio_mode = "auto"` to avoid needing `@pytest.mark.asyncio` everywhere
- Add `pythonpath = ["backend"]` to avoid `sys.path` manipulation
- Set `testpaths = ["tests"]`

### 4. Add CI Coverage Enforcement

Add a coverage threshold to prevent regressions:
```
pytest --cov=backend/vulnpilot --cov-fail-under=30 tests/
```
Start at 30% (achievable with the Priority 1-3 recommendations), then ratchet up.

---

## Estimated Impact

| Priority | New Tests | Stmts Covered | Coverage After |
|---|---|---|---|
| P1: Guardrails | ~12 tests | ~67 | 13% |
| P2: Auth | ~12 tests | ~171 | 16% |
| P3: API Routes | ~10 tests | ~200 | 19% |
| P4: Drift | ~8 tests | ~100 | 21% |
| P5: Scanners | ~30 tests | ~500 | 28% |
| P6: Reports | ~8 tests | ~200 | 31% |
| P7: Resilience | ~6 tests | ~60 | 32% |
| P8: Pipeline | ~6 tests | ~150 | 34% |
| Migrate run_tests.py | ~15 tests | ~300 | 39% |

Implementing P1-P6 and the `run_tests.py` migration would bring coverage from **12% to ~39%**, covering all critical security and business-logic paths.
