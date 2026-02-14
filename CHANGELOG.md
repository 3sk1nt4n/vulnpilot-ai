# Changelog

All notable changes to VulnPilot AI are documented here.

## [1.0.0] - 2026-02-14

### Added
- 5 AI agents with Triple-Lock safety system (Patent Pending)
- VPRS scoring engine with configurable YAML weights
- 6 scanner integrations: Tenable.io, Qualys VMDR, Rapid7 InsightVM, OpenVAS, Wazuh, Nessus File
- Cloud compliance layer: Prowler (500+ checks), Cloud Custodian (5 built-in policies)
- OCSF v1.1 parser for Prowler JSON Lines output
- AWS/Azure/GCP asset inventory collectors
- 8 threat intelligence sources with parallel enrichment
- Dark web monitoring: Shodan, VulDB, Recorded Future, Flashpoint
- Adversarial cross-model debate (Lock 2) with Claude, GPT-4o, Ollama
- Drift detector (Lock 3) with tiered recheck intervals
- JWT authentication with RBAC (admin, analyst, viewer, api roles)
- 4-layer guardrails: input filtering, output scanning, escalation detection, RAG defense
- PagerDuty ticket provider with Events API v2, dedup, auto-resolve
- Cloud compliance CSV and Markdown exports
- Weekly trend reports with cloud compliance section
- 51 API endpoints with Swagger/ReDoc documentation
- Setup wizard with Quick Paste, Visual Setup, and Docs tabs (35 integrations)
- Demo mode with 47 CVEs and 10 Prowler sample findings
- Docker Compose with profiles: local (Ollama), cloud (Prowler)
- Alembic database migrations (7 tables)
- Test suite: 4 files, 1,135 lines, 22+ cloud tests
- GitLab CI/CD pipeline with lint, test, build, deploy stages

### Architecture
- 76 Python files, 15,327 lines
- 7,445 lines HTML (dashboard + setup wizard)
- PostgreSQL 16 + Redis 7 + Celery
- FastAPI with async/await throughout
- Factory pattern for all providers (scanners, LLM, tickets, threat intel)
- Circuit breaker + rate limiter + exponential retry on all external APIs
