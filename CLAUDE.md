# CLAUDE.md — VulnPilot AI

This file provides context for AI assistants working on this codebase.

## Project Overview

VulnPilot AI is an **agentic vulnerability management orchestrator** built by Solvent CyberSecurity. It sits above existing vulnerability scanners (Tenable, Qualys, Rapid7, OpenVAS, Wazuh) and uses 5 AI agents with a patented Triple-Lock safety system to autonomously triage CVEs into actionable remediation tickets.

The core innovation is VPRS (VulnPilot Priority Risk Score), which replaces CVSS-only prioritization by combining EPSS exploit probability, CISA KEV status, dark web activity, asset criticality, and compensating controls into a single 0-100 score.

**License:** Proprietary. Copyright Solvent CyberSecurity LLC.

## Tech Stack

- **Language:** Python 3.12
- **Framework:** FastAPI with async/await, Pydantic v2
- **Database:** PostgreSQL 16 (SQLAlchemy ORM, Alembic migrations)
- **Cache/Queue:** Redis 7, Celery (background tasks)
- **LLM Providers:** Anthropic Claude, OpenAI GPT-4o, Ollama (local)
- **Frontend:** Vanilla HTML/JS/CSS (zero JS dependencies, single-page)
- **Container:** Docker Compose with multi-profile support

## Repository Structure

```
vulnpilot-ai/
├── backend/
│   ├── vulnpilot/             # Main Python package
│   │   ├── agents/            # 5 AI agents (pipeline.py, weekly_report.py)
│   │   ├── api/               # FastAPI routes + Pydantic schemas
│   │   ├── auth/              # JWT auth + RBAC middleware
│   │   ├── cloud/             # Prowler, OCSF parser, asset collectors, Custodian
│   │   ├── cmdb/              # Asset inventory (ServiceNow CMDB, CSV import)
│   │   ├── db/                # PostgreSQL session + async engine
│   │   ├── llm/               # LLM provider abstraction (anthropic, openai, ollama)
│   │   ├── reports/           # Report generation (Markdown, JSON)
│   │   ├── safety/            # Safety enforcement layer
│   │   ├── scanners/          # 6 scanner providers + resilience module
│   │   ├── scoring/           # VPRS engine + hard rules engine
│   │   ├── threatintel/       # 8 threat intel sources + parallel enrichment
│   │   ├── tickets/           # ServiceNow, Jira, PagerDuty, Console
│   │   ├── config.py          # Pydantic settings (reads .env)
│   │   ├── demo_seed.py       # Demo data seeder (47 CVEs + cloud findings)
│   │   ├── drift.py           # Lock 3 drift detector
│   │   ├── guardrails.py      # 4-layer input/output security
│   │   ├── live_seed.py       # Live scanner data seeder
│   │   ├── main.py            # FastAPI app entry point
│   │   ├── models.py          # SQLAlchemy ORM models (7 tables)
│   │   └── tasks.py           # Celery background tasks
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── index.html             # Dashboard SPA (~3,900 lines)
│   └── setup.html             # Setup wizard
├── config/
│   ├── hard_rules.yaml        # Lock 1 override rules (non-negotiable)
│   ├── sla_tiers.yaml         # SLA deadlines by severity
│   ├── vprs_weights.yaml      # Scoring weight configuration (must sum to 1.0)
│   └── custodian/             # Cloud Custodian YAML policies
├── data/
│   ├── prowler_sample/        # Demo Prowler OCSF output
│   └── cmdb_assets.csv        # Sample asset inventory
├── tests/                     # Test suite
│   ├── test_vprs.py           # VPRS scoring unit tests
│   ├── test_cloud.py          # Cloud module tests (22 tests)
│   ├── run_tests.py           # Integration test scenarios
│   ├── scenario_library.py    # Test scenario definitions
│   └── integration_test.sh    # Shell-based integration tests
├── alembic/                   # Database migrations
├── docs/                      # Gap analysis + landing page HTML
├── landing/                   # Marketing landing page
├── docker-compose.yml         # Full stack (5 services + 2 profiles)
├── .env.example               # Template environment file
├── .gitlab-ci.yml             # CI/CD pipeline (lint, test, build, deploy)
└── setup.sh                   # Automated setup script
```

## Key Architecture Patterns

### Factory Pattern for All Providers

Every external integration uses a factory pattern. Providers are selected via environment variables and instantiated through factory functions:

- `llm/factory.py` → `get_llm_provider()` returns Anthropic, OpenAI, or Ollama
- `scanners/factory.py` → `get_scanner_providers()` returns list of scanner clients
- `tickets/factory.py` → `get_ticket_provider()` returns ServiceNow, Jira, PagerDuty, or Console
- `threatintel/factory.py` → `get_threatintel_provider()` returns API or local provider
- `cmdb/factory.py` → `get_cmdb_provider()` returns CMDB provider

### Provider Base Classes

Each provider type has an abstract base class defining the interface:

- `llm/base.py` → `LLMProvider(ABC)` with `DebateResult`, `JustificationResult`
- `scanners/base.py` → `ScannerProvider(ABC)` with `NormalizedVuln` dataclass
- `tickets/base.py` → `TicketProvider(ABC)` with `TicketResult`
- `threatintel/base.py` → `ThreatIntelProvider(ABC)` with `ThreatIntelResult`

### Normalized Data Model

All scanner data normalizes to `NormalizedVuln` (defined in `scanners/base.py`) before entering the VPRS pipeline. This is the central data contract between scanners and scoring.

### Triple-Lock Safety System

1. **Lock 1 — Hard Rules** (`config/hard_rules.yaml`, `scoring/hard_rules.py`): YAML-defined rules enforced in code before AI scoring. CISA KEV = always Critical. Ransomware = always Critical. Cannot be overridden by AI.
2. **Lock 2 — Adversarial Debate** (`llm/base.py`): Two independent LLM providers score each CVE. Disagreements >15 points flag for human review.
3. **Lock 3 — Drift Detector** (`drift.py`, `tasks.py`): Background Celery tasks recheck threat intel periodically. Score auto-promotes on EPSS spikes, KEV additions, or new dark web activity.

### VPRS Scoring Pipeline (`agents/pipeline.py`)

5-step pipeline:
1. Ingest raw scanner data → `NormalizedVuln`
2. Enrich with EPSS + KEV + dark web intel → `ThreatIntelResult`
3. Agent 1 (Correlator) eliminates CVSS noise
4. Agent 2 (Context Mapper) applies environment context
5. VPRS scoring → Hard Rules → Adversarial Debate → Ticket creation

### Configuration via Environment

All configuration flows through `config.py` (`Settings` class using `pydantic-settings`). The `.env` file is the single switch between local and cloud modes:

- `LLM_PROVIDER=ollama` → Free local development
- `LLM_PROVIDER=anthropic` → Production with Claude
- `LLM_PROVIDER=openai` → Alternative with GPT-4o

### Database Models (`models.py`)

7 SQLAlchemy ORM tables: `vulnerabilities`, `assets`, `vprs_scores`, `tickets`, `audit_log`, `drift_events`, `cloud_findings`. Uses PostgreSQL UUID primary keys and async sessions (`asyncpg`).

## Development Commands

### Running the Application

```bash
# Docker Compose (recommended)
docker compose up -d

# Local development
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn vulnpilot.main:app --reload --port 8000
```

### Running Tests

Tests run from the repository root, not from `backend/`:

```bash
# All tests
pytest tests/ -v

# VPRS scoring tests
pytest tests/test_vprs.py -v

# Cloud module tests (22 tests)
pytest tests/test_cloud.py -v

# Integration scenarios
pytest tests/run_tests.py -v
```

Test files add `backend/` to `sys.path` so imports resolve as `from vulnpilot.scoring.vprs import VPRSEngine`.

### Linting

```bash
# Ruff linting (E, F, W rules; E501 line length ignored)
ruff check backend/vulnpilot/ --select E,F,W --ignore E501

# Syntax validation (all Python files must parse)
find backend/ -name "*.py" -exec python -c "import ast; ast.parse(open('{}').read())" \;
```

### Formatting

```bash
black backend/vulnpilot/
```

### Database Migrations

```bash
alembic upgrade head
```

## Coding Conventions

### Commit Messages

Use conventional commits:

```
feat: add Azure asset collector
fix: resolve bcrypt crash on Python 3.12
docs: update README with cloud compliance section
test: add 22 cloud module unit tests
```

### Branch Naming

- `feature/description` for new features
- `fix/description` for bug fixes
- `hotfix/description` for urgent production fixes

### Python Style

- Python 3.12 with type hints
- Dataclasses for value objects (`VPRSResult`, `NormalizedVuln`, `ThreatIntelResult`, etc.)
- ABC for provider interfaces
- `async/await` for all I/O operations (database, HTTP, LLM calls)
- `structlog` for structured logging
- Pydantic v2 models for API schemas
- Factory functions (not dependency injection frameworks)
- Line length is not enforced (E501 is ignored in ruff)

### YAML Configuration

- VPRS weights in `config/vprs_weights.yaml` must sum to 1.0
- Hard rules in `config/hard_rules.yaml` define non-negotiable overrides
- SLA tiers in `config/sla_tiers.yaml` map severity to remediation deadlines
- Cloud Custodian policies in `config/custodian/`

### Security Considerations

- Never log or expose credentials in API responses
- 4-layer guardrails protect LLM interactions (input filtering, output scanning, escalation detection, RAG poisoning defense)
- JWT authentication with bcrypt password hashing when `AUTH_ENABLED=true`
- All external API calls use circuit breakers, rate limiters, and exponential retry
- Input validation at system boundaries using Pydantic models

## Environment Variables

See `.env.example` for the full list. Key variables:

| Variable | Purpose | Values |
|---|---|---|
| `LLM_PROVIDER` | AI backend | `ollama`, `anthropic`, `openai` |
| `SCANNER_PROVIDERS` | Comma-separated scanner list | `tenable,qualys,rapid7,openvas,wazuh,nessus_file,cloud` |
| `TICKET_PROVIDER` | Ticket system | `console`, `servicenow`, `jira`, `pagerduty` |
| `AUTH_ENABLED` | Enable JWT auth | `true`, `false` (default: false for dev) |
| `CLOUD_DEMO_MODE` | Use sample cloud data | `true`, `false` |
| `DATABASE_URL` | PostgreSQL connection | `postgresql+asyncpg://...` |
| `REDIS_URL` | Redis connection | `redis://...` |

## CI/CD Pipeline (`.gitlab-ci.yml`)

4 stages: `lint` → `test` → `build` → `deploy`

- **lint:python** — ruff with `--select E,F,W --ignore E501`
- **lint:syntax** — AST parse validation on all Python files
- **test:unit** — pytest against `test_vprs.py` and `test_cloud.py` (requires postgres + redis services)
- **build:docker** — Docker image build (main branch and tags only)
- **deploy** — Manual staging/production deploy

## Docker Services

| Service | Description | Port |
|---|---|---|
| `api` | FastAPI + Uvicorn | 8001→8000 |
| `postgres` | PostgreSQL 16 | 5433→5432 |
| `redis` | Redis 7 | 6380→6379 |
| `celery-worker` | Background task worker | — |
| `celery-beat` | Task scheduler (drift, SLA) | — |
| `prowler` | Cloud compliance (profile: cloud) | — |

## Common Pitfalls

- **Test path:** Tests must run from the repo root (`pytest tests/ -v`), not from `backend/`.
- **VPRS weights:** If modifying `config/vprs_weights.yaml`, weights must sum to 1.0 or scoring will be incorrect.
- **Hard rules priority:** Rules in `config/hard_rules.yaml` have a `priority` field; lower numbers = higher priority, evaluated first.
- **Async database:** All DB operations use `asyncpg`; the sync URL is only for Alembic migrations.
- **Frontend is static:** The dashboard is a single-file HTML SPA served by FastAPI's `StaticFiles`. No build step required.
- **Provider singletons:** The pipeline and providers are lazily initialized as module-level singletons in `api/routes.py`. Be aware of this when testing.
- **Import paths:** Backend code uses `vulnpilot.*` imports. Tests prepend `backend/` to `sys.path` to make this work without installing the package.
