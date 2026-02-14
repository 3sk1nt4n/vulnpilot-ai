# VulnPilot AI

**Agentic Vulnerability Management Orchestrator**

Zero Noise. Zero Delay. Zero Missed Patches.

By [Solvent CyberSecurity](https://solventcyber.com) | v1.0.0

---

## What Is VulnPilot?

VulnPilot AI sits above your existing vulnerability scanners (Tenable, Qualys, Rapid7, OpenVAS, Wazuh) and uses 5 AI agents with a patented Triple-Lock safety system to autonomously triage 10,000+ CVEs down to 15-25 actionable tickets with plain-English justifications.

It replaces the broken CVSS-only workflow with VPRS (VulnPilot Priority Risk Score), which combines EPSS exploit probability, CISA KEV status, dark web activity, asset criticality, and real-world threat intelligence into a single score that reflects actual risk.

**The result:** 85% noise elimination, 55% CVSS-vs-VPRS flips, and zero missed actively-exploited vulnerabilities.

## The Problem

CVSS prioritization is wrong 96% of the time. Only 2% of CVEs are ever exploited, but CVSS flags 53% as high/critical. Security teams drown in false urgency while real threats slip through.

```
CVE-2024-21887    CVSS 9.1  -->  VPRS 12.0  (INFO)       <-- NOISE: no exploit, no KEV
CVE-2024-3400     CVSS 7.5  -->  VPRS 100.0 (CRITICAL)   <-- REAL: in KEV, dark web, EPSS 0.97
```

VulnPilot fixes this by scoring what matters: is anyone actually exploiting it?

## Architecture

```
                    +---------------------------+
                    |     VulnPilot Dashboard    |
                    |  (Single-page HTML + JS)   |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |     FastAPI Backend        |
                    |     51 API endpoints       |
                    +---+-----+-----+-----+----+
                        |     |     |     |
               +--------+  +-+--+ ++-+-+ ++-------+
               | Agent 1 | |Ag 2| |Ag 3| | Ag 4/5 |
               | Scoring | |Lock| |Drift| | Report |
               +---------+ +----+ +-----+ +--------+
                    |           |
        +-----------+-----------+-----------+
        |           |           |           |
   +----v---+ +----v----+ +---v----+ +----v----+
   |Tenable | | Qualys  | |Rapid7  | |OpenVAS  |
   |Wazuh   | | Nessus  | |Prowler | |Custodian|
   +--------+ +---------+ +--------+ +---------+
```

**Hybrid deployment:** One codebase, two modes, switched by a single `.env` file.

- `LLM_PROVIDER=ollama` -- Free local dev with Llama 3.3 ($0)
- `LLM_PROVIDER=anthropic` -- Production SaaS with Claude Sonnet
- `LLM_PROVIDER=openai` -- Alternative with GPT-4o

## Triple-Lock Safety System (Patent Pending)

VulnPilot never trusts a single AI model. Every score passes through three independent safety locks:

**Lock 1 - Hard Rules (Code, not AI)**
Non-negotiable overrides that no AI model can bypass. CISA KEV = always Critical. Ransomware-linked = always Critical. EPSS > 0.7 = minimum High. These are enforced in code, not prompts.

**Lock 2 - Adversarial Cross-Model Debate**
Two different AI providers (Claude + GPT-4o, or Claude + Ollama) independently score each CVE. If they disagree by more than 15 points, the CVE is flagged for human review. Neither model can see the other's reasoning.

**Lock 3 - Drift Detector**
Background Celery tasks recheck threat intelligence every 1-6 hours (tiered by asset criticality). If EPSS spikes, KEV adds a CVE, or dark web mentions appear, the score auto-promotes and a new ticket is created without waiting for the next scan.

## Features

**Vulnerability Scoring**
- VPRS scoring engine with configurable weights
- EPSS, CVSS, KEV, dark web, asset tier, internet-facing, MITRE ATT&CK inputs
- Hard rule overrides (YAML-configurable)
- 85% noise elimination rate

**Scanner Integrations (6 providers)**
- Tenable.io -- multi-CVE, EPSS/VPR/CVSS4, circuit breaker
- Qualys VMDR -- QID-to-CVE KB lookup
- Rapid7 InsightVM -- v4 API with cursor pagination
- OpenVAS -- native GMP XML protocol
- Wazuh -- indexer-first with REST fallback
- Nessus file import -- .nessus XML parsing (air-gapped)

**Cloud Compliance (Prowler + Custodian)**
- Prowler integration -- 500+ checks, 39 frameworks (CIS, SOC2, HIPAA, PCI, NIST)
- OCSF v1.1 parser -- automatic JSON Lines parsing
- Cloud Custodian -- 5 built-in YAML policies + custom policy engine
- AWS asset inventory -- EC2, RDS, S3, Lambda, ELB via boto3
- Azure asset inventory -- VMs, Storage Accounts, SQL Servers via Azure SDK
- GCP asset inventory -- Compute Instances, GCS Buckets, Cloud SQL
- Demo mode with sample data (no cloud account needed)

**Threat Intelligence (8 sources)**
- EPSS -- batch API (30 CVEs per call)
- CISA KEV -- cached daily download
- NVD/NIST -- rate-limited with optional API key
- AlienVault OTX -- pulse-based enrichment
- GreyNoise -- scanning/noise detection
- abuse.ch -- ThreatFox + URLhaus (Auth-Key since June 2025)
- Dark web monitor -- Shodan CVEDB, Shodan Exploits, VulDB, Recorded Future, Flashpoint
- MITRE ATT&CK -- tactic/technique mapping

**AI Providers (3 + local)**
- Anthropic Claude Sonnet -- primary or challenger
- OpenAI GPT-4o -- cross-model debate partner
- Ollama (local) -- Llama 3.3, Mistral, CodeLlama ($0, air-gapped)
- Hot-swap between providers without restart

**Ticket Systems (4 providers)**
- ServiceNow -- incident creation with SLA tracking
- Jira Cloud -- issue creation with project assignment
- PagerDuty -- Events API v2 with dedup and auto-resolve (VPRS 90+ only)
- Console -- dev mode logging

**Notifications (5 channels)**
- Slack webhooks with VPRS badges
- Microsoft Teams adaptive cards
- Email (SMTP/STARTTLS)
- PagerDuty alerting
- Generic webhook (SIEM, SOAR, Zapier, n8n)

**Reports and Exports**
- Weekly/monthly trend reports (JSON + Markdown)
- Executive, technical, compliance, and board styles
- Cloud compliance CSV and Markdown exports
- Framework mapping: PCI DSS 4.0, NIST CSF, NIST 800-53, SOC2, ISO 27001, HIPAA, CISA BOD

**Authentication and RBAC**
- JWT-based authentication (PyJWT + bcrypt)
- Four roles: admin, analyst, viewer, api
- User management API (create, update, delete)
- `AUTH_ENABLED=false` for development (default)
- `AUTH_ENABLED=true` for production

**Security (Defense-in-Depth)**
- 4-layer guardrails: input filtering, output scanning, multi-turn escalation detection, RAG poisoning defense
- Jailbreak pattern detection (DAN, evil persona, grandma trick, prefix injection)
- System prompt extraction blocking
- No credentials in logs or API responses

## Quick Start

### Option 1: Docker Compose (recommended)

```bash
git clone https://gitlab.com/solventcyber/vulnpilot-ai.git
cd vulnpilot-ai
cp .env.example .env
# Edit .env with your API keys

docker compose up -d
# Dashboard: http://localhost:8000
# API docs:  http://localhost:8000/docs
# Setup:     http://localhost:8000/setup
```

### Option 2: Local Development

```bash
git clone https://gitlab.com/solventcyber/vulnpilot-ai.git
cd vulnpilot-ai

# Backend
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn vulnpilot.main:app --reload --port 8000

# In another terminal: Redis + PostgreSQL
docker compose up -d redis postgres
```

### Option 3: Fully Local (Air-Gapped, $0)

```bash
docker compose --profile local up -d
# This starts: backend + postgres + redis + ollama (auto-pulls llama3.3)
# No API keys needed. No internet required after first pull.
```

## Environment Variables

Create a `.env` file in the project root. The setup page at `/setup` has a Quick Paste tab that generates this for you.

### Required (pick one LLM)

```bash
# AI Provider (pick one)
LLM_PROVIDER=anthropic              # or: openai, ollama
ANTHROPIC_API_KEY=sk-ant-...        # if using Claude
OPENAI_API_KEY=sk-...               # if using GPT-4o
OLLAMA_URL=http://ollama:11434      # if using local (auto in Docker)
```

### Scanner (pick one or more)

```bash
SCANNER_PROVIDERS=tenable,cloud     # comma-separated list

# Tenable.io
TENABLE_ACCESS_KEY=your-key
TENABLE_SECRET_KEY=your-secret

# Qualys
QUALYS_API_URL=https://qualysapi.qualys.com
QUALYS_USERNAME=user
QUALYS_PASSWORD=pass

# Rapid7
RAPID7_API_KEY=your-key
RAPID7_REGION=us

# Cloud Compliance
CLOUD_DEMO_MODE=true                # default: sample data, no cloud needed
AWS_ACCESS_KEY_ID=AKIA...           # for live AWS scans
AWS_SECRET_ACCESS_KEY=secret
AWS_DEFAULT_REGION=us-east-1
```

### Tickets (pick one)

```bash
TICKET_PROVIDER=servicenow          # or: jira, pagerduty, console

# ServiceNow
SERVICENOW_INSTANCE=https://dev12345.service-now.com
SERVICENOW_USERNAME=admin
SERVICENOW_PASSWORD=pass

# Jira
JIRA_URL=https://your-org.atlassian.net
JIRA_EMAIL=you@company.com
JIRA_API_TOKEN=token
JIRA_PROJECT_KEY=SEC

# PagerDuty
PAGERDUTY_ROUTING_KEY=your-routing-key
```

### Notifications (optional)

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=app-password
```

### Authentication (production)

```bash
AUTH_ENABLED=true
AUTH_SECRET_KEY=your-random-256bit-secret
AUTH_ADMIN_PASSWORD=strong-password
AUTH_TOKEN_EXPIRY_HOURS=8
```

## Project Structure

```
vulnpilot-ai/
|
|-- backend/
|   |-- vulnpilot/
|   |   |-- agents/           # 5 AI agents (scoring pipeline, weekly reports)
|   |   |-- api/              # FastAPI routes (51 endpoints)
|   |   |-- auth/             # JWT authentication + RBAC middleware
|   |   |-- cloud/            # Prowler, OCSF parser, asset collectors, Custodian
|   |   |-- cmdb/             # Asset inventory (ServiceNow CMDB, CSV import)
|   |   |-- db/               # PostgreSQL session + migrations
|   |   |-- llm/              # Claude, GPT-4o, Ollama providers + factory
|   |   |-- reports/          # Report generation (PDF, Markdown, Excel)
|   |   |-- safety/           # Safety enforcement layer
|   |   |-- scanners/         # 6 scanner providers + resilience module
|   |   |-- scoring/          # VPRS engine + hard rules
|   |   |-- threatintel/      # 8 threat intel sources + parallel enrichment
|   |   |-- tickets/          # ServiceNow, Jira, PagerDuty, Console
|   |   |-- config.py         # Pydantic settings
|   |   |-- demo_seed.py      # Demo data seeder (47 CVEs + cloud findings)
|   |   |-- guardrails.py     # 4-layer input/output security
|   |   |-- models.py         # SQLAlchemy ORM (7 tables)
|   |   |-- tasks.py          # Celery background tasks (drift, SLA, reports)
|   |   +-- main.py           # FastAPI app entry point
|   |-- requirements.txt
|   +-- Dockerfile
|
|-- frontend/
|   |-- index.html            # Dashboard (single-page, 3,900 lines)
|   +-- setup.html            # Setup wizard (Quick Paste + Visual Setup + Docs)
|
|-- config/
|   |-- hard_rules.yaml       # Lock 1 override rules
|   |-- sla_tiers.yaml        # SLA deadlines by severity
|   |-- vprs_weights.yaml     # Scoring weight configuration
|   +-- custodian/            # Cloud Custodian YAML policies
|
|-- data/
|   |-- prowler_sample/       # Demo Prowler OCSF output (10 findings)
|   +-- cmdb_assets.csv       # Sample asset inventory
|
|-- alembic/                  # Database migrations
|-- tests/                    # Test suite (4 files, 1,135 lines)
|-- landing/                  # Marketing landing page
|-- docs/                     # Gap analysis + documentation
|-- docker-compose.yml        # Full stack (7 services)
+-- .env.example              # Template environment file
```

## API Endpoints (51 total)

### Core

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/status` | Detailed system status with provider health |
| POST | `/api/v1/score` | Score a single CVE |
| POST | `/api/v1/batch` | Score multiple CVEs |
| GET | `/api/v1/results` | Get all scored results |

### Cloud Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/cloud/scan` | Trigger Prowler scan |
| GET | `/api/v1/cloud/findings` | Parsed compliance findings |
| GET | `/api/v1/cloud/summary` | Compliance percentage and breakdown |
| GET | `/api/v1/cloud/assets` | Cloud asset inventory |
| GET | `/api/v1/cloud/export/csv` | Export findings as CSV |
| GET | `/api/v1/cloud/export/markdown` | Export findings as Markdown |
| POST | `/api/v1/cloud/credentials/validate` | Validate cloud credentials |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Get JWT token |
| GET | `/api/v1/auth/me` | Current user info |
| POST | `/api/v1/auth/register` | Create user (admin only) |
| GET | `/api/v1/auth/users` | List users (admin only) |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/report/generate` | Generate report (weekly, monthly, compliance) |
| GET | `/api/v1/report/compliance` | Compliance framework mapping |

Full API documentation available at `/docs` (Swagger UI) and `/redoc` (ReDoc).

## Database

PostgreSQL with SQLAlchemy ORM. 7 tables:

- `vulnerabilities` -- all ingested CVEs with raw scanner data
- `assets` -- asset inventory from CMDB/scanners
- `vprs_scores` -- VPRS scores with full audit trail
- `tickets` -- created tickets with SLA tracking
- `audit_log` -- every scoring decision logged
- `drift_events` -- threat intel changes detected by Lock 3
- `cloud_findings` -- Prowler/Custodian compliance results

Migrations managed by Alembic:

```bash
alembic upgrade head
```

## Testing

```bash
# Run all tests
cd backend
pytest tests/ -v

# Run specific test modules
pytest tests/test_vprs.py -v       # VPRS scoring tests
pytest tests/test_cloud.py -v      # Cloud module tests (22 tests)
pytest tests/run_tests.py -v       # Integration scenarios
```

## Docker Services

```yaml
services:
  backend:    FastAPI + Uvicorn (port 8000)
  postgres:   PostgreSQL 16 (port 5432)
  redis:      Redis 7 (port 6379)
  celery:     Background task worker
  beat:       Celery scheduler (drift, SLA, reports)
  ollama:     Local LLM (profile: local)
  prowler:    Cloud compliance scanner (profile: cloud)
```

Start specific profiles:

```bash
# Standard (API keys required)
docker compose up -d

# Fully local with Ollama
docker compose --profile local up -d

# With cloud compliance scanning
docker compose --profile cloud up -d

# Everything
docker compose --profile local --profile cloud up -d
```

## Configuration

### VPRS Weights (`config/vprs_weights.yaml`)

```yaml
cvss_base: 0.25
epss_score: 0.25
asset_criticality: 0.20
threat_intel: 0.15
environmental: 0.15
```

### Hard Rules (`config/hard_rules.yaml`)

```yaml
rules:
  - name: CISA KEV
    condition: in_kev == true
    action: set_critical
    reason: "CISA Known Exploited Vulnerability - mandatory patch"

  - name: Ransomware Linked
    condition: ransomware_linked == true
    action: set_critical
    reason: "CVE linked to active ransomware campaigns"
```

### SLA Tiers (`config/sla_tiers.yaml`)

```yaml
critical: 72     # hours
high: 168        # 7 days
medium: 720      # 30 days
low: 2160        # 90 days
```

## Integration Count: 35

| Category | Integrations |
|----------|-------------|
| Scanners | Tenable.io, Qualys VMDR, Rapid7 InsightVM, OpenVAS, Wazuh, Nessus File |
| Cloud | Prowler (AWS/Azure/GCP), Cloud Custodian, AWS Inventory, Azure Inventory, GCP Inventory |
| Threat Intel | EPSS, CISA KEV, NVD, OTX, GreyNoise, abuse.ch, MITRE ATT&CK |
| Dark Web | Shodan CVEDB, Shodan Exploits, VulDB, Recorded Future, Flashpoint |
| Tickets | ServiceNow, Jira Cloud, PagerDuty |
| Notifications | Slack, Teams, Email, PagerDuty Alerts, Generic Webhook |
| AI Providers | Claude, GPT-4o, Ollama |
| CMDB | ServiceNow CMDB, CSV Import |

## Tech Stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy, Celery, asyncio
- **Database:** PostgreSQL 16 with Alembic migrations
- **Cache/Queue:** Redis 7
- **Frontend:** Vanilla HTML/JS/CSS (zero dependencies, single-page)
- **Auth:** PyJWT, bcrypt (SHA-256 fallback for dev)
- **Cloud:** boto3, Azure SDK, GCP client libraries
- **Compliance:** Prowler, Cloud Custodian
- **Container:** Docker Compose with multi-profile support

## Codebase Stats

```
Python files:    76
Python lines:    15,327
HTML lines:      7,445
API endpoints:   51
Test files:      4 (1,135 lines)
DB tables:       7
Total files:     103
```

## Compliance Frameworks Mapped

VulnPilot maps every finding to industry frameworks:

- PCI DSS 4.0 (6.3.3 patching, 11.3.1 scanning)
- NIST CSF (ID.RA-1, RS.MI-3)
- NIST 800-53 (RA-5, SI-2)
- SOC 2 (CC7.1)
- ISO 27001 (A.12.6.1)
- HIPAA (164.312)
- CISA BOD 22-01 (KEV remediation)
- CIS Benchmarks (via Prowler, 39 frameworks)
- GDPR, FedRAMP, MITRE ATT&CK (via Prowler)

## Roadmap

- [ ] Multi-tenant isolation with tenant-scoped database
- [ ] SSO/SAML integration (Okta, Azure AD)
- [ ] Real-time WebSocket dashboard updates
- [ ] Autonomous remediation playbooks (Ansible, Terraform)
- [ ] Mobile app (React Native)
- [ ] SOC 2 Type II certification for Solvent CyberSecurity

## License

Proprietary. Copyright 2025 Solvent CyberSecurity LLC. All rights reserved.

## Contact

- **Company:** [Solvent CyberSecurity](https://solventcyber.com)
- **Author:** Adil Eskintan
- **Email:** info@solventcyber.com
