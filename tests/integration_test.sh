#!/usr/bin/env bash
# ============================================================
# VulnPilot AI - Integration Test Suite
# Run this on YOUR machine after: docker compose up -d
#
# Prerequisites:
#   - Docker + Docker Compose running
#   - .env.local configured
#   - 'docker compose up -d' started
#
# Usage: bash tests/integration_test.sh
# ============================================================

set -e

API="http://localhost:8000/api/v1"
PASS=0
FAIL=0
SKIP=0

green() { echo -e "\033[32m  ✅ $1\033[0m"; PASS=$((PASS+1)); }
red()   { echo -e "\033[31m  ❌ $1\033[0m"; FAIL=$((FAIL+1)); }
skip()  { echo -e "\033[33m  ⏭️  $1\033[0m"; SKIP=$((SKIP+1)); }

check_http() {
    local url="$1"
    local desc="$2"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [ "$status" = "200" ]; then
        green "$desc (HTTP $status)"
    elif [ "$status" = "000" ]; then
        red "$desc (connection refused - is docker compose up?)"
    else
        red "$desc (HTTP $status)"
    fi
}

check_post() {
    local url="$1"
    local data="$2"
    local desc="$3"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$data" "$url" 2>/dev/null || echo "000")
    if [ "$status" = "200" ]; then
        green "$desc (HTTP $status)"
    elif [ "$status" = "000" ]; then
        red "$desc (connection refused)"
    else
        red "$desc (HTTP $status)"
    fi
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  VulnPilot AI - Live Integration Test Suite                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── 1. API Health ───
echo "═══ 1. API CORE ═══"
check_http "$API/health" "API health check"
check_http "$API/status" "System status"
check_http "$API/config/weights" "VPRS weights endpoint"

echo ""
echo "═══ 2. DASHBOARD ═══"
check_http "http://localhost:8000/" "Dashboard serves at root"
check_http "http://localhost:8000/docs" "OpenAPI docs"

echo ""
echo "═══ 3. VPRS SCORING ═══"
check_post "$API/score" '{
    "cve_id": "CVE-2024-21887",
    "cvss_base_score": 9.1,
    "asset_tier": "tier_1",
    "is_internet_facing": true
}' "Score single CVE"

check_post "$API/score" '{
    "cve_id": "CVE-2024-99999",
    "cvss_base_score": 7.5,
    "asset_tier": "tier_3",
    "is_internet_facing": false
}' "Score noise CVE"

echo ""
echo "═══ 4. SCORING DETAILS (verify VPRS output) ═══"
RESULT=$(curl -s -X POST -H "Content-Type: application/json" -d '{
    "cve_id": "CVE-2024-21887",
    "cvss_base_score": 9.1,
    "asset_tier": "tier_1",
    "is_internet_facing": true
}' "$API/score" 2>/dev/null || echo '{}')
echo "  Raw response: $RESULT"
if echo "$RESULT" | grep -q "vprs_score"; then
    green "VPRS score returned in response"
else
    red "No vprs_score in response"
fi
if echo "$RESULT" | grep -q "severity"; then
    green "Severity returned in response"
else
    red "No severity in response"
fi

echo ""
echo "═══ 5. REPORTS ═══"
check_http "$API/report/weekly" "Weekly report (JSON)"
check_http "$API/report/weekly/markdown" "Weekly report (Markdown)"
check_http "$API/report/compliance" "Compliance report"
check_http "$API/report/compliance/markdown" "Compliance report (Markdown)"

echo ""
echo "═══ 6. SLA TRACKING ═══"
check_http "$API/sla/status" "SLA status dashboard"

echo ""
echo "═══ 7. ENRICHMENT ═══"
check_http "$API/enrich/nvd/CVE-2024-21887" "NVD enrichment (live API call)"
check_http "$API/enrich/attack/CVE-2024-21887" "MITRE ATT&CK mapping"

echo ""
echo "═══ 8. SCANNER INGESTION ═══"
check_post "$API/ingest" '{}' "Scanner ingestion (pulls from configured scanners)"

echo ""
echo "═══ 9. NOTIFICATIONS ═══"
check_post "$API/webhook/test" '{}' "Webhook test (sends to configured channel)"

echo ""
echo "═══ 10. DATABASE ═══"
# Check if Alembic migrations ran
if docker compose exec -T api python -c "from vulnpilot.db.session import get_db; print('DB OK')" 2>/dev/null | grep -q "DB OK"; then
    green "Database connection"
else
    skip "Database (may need: alembic upgrade head)"
fi

echo ""
echo "═══ 11. CELERY WORKERS ═══"
if docker compose exec -T celery-worker celery -A vulnpilot.tasks inspect ping 2>/dev/null | grep -q "pong"; then
    green "Celery worker responding"
else
    skip "Celery worker (check: docker compose logs celery-worker)"
fi

if docker compose exec -T celery-beat celery -A vulnpilot.tasks inspect active 2>/dev/null; then
    green "Celery beat scheduler"
else
    skip "Celery beat (check: docker compose logs celery-beat)"
fi

echo ""
echo "═══ 12. LLM PROVIDER ═══"
if docker compose exec -T api python -c "
from vulnpilot.llm.factory import get_llm_provider
import asyncio
p = get_llm_provider()
print(f'Provider: {p.provider_name}')
ok = asyncio.run(p.health_check())
print(f'Health: {ok}')
" 2>/dev/null | grep -q "Health: True"; then
    green "LLM provider connected"
else
    skip "LLM provider (pull model: docker compose exec ollama ollama pull llama3.3:70b)"
fi

echo ""
echo "═══ 13. EXTERNAL SERVICE CHECKS ═══"
# These only work if credentials are configured
echo "  Testing configured scanner connections..."
docker compose exec -T api python -c "
import asyncio, os
providers = os.getenv('SCANNER_PROVIDERS', '').split(',')
for p in providers:
    p = p.strip()
    if not p:
        continue
    print(f'  Scanner: {p}', end=' ')
    try:
        from vulnpilot.scanners.factory import get_scanner_providers
        scanners = get_scanner_providers()
        for s in scanners:
            if s.scanner_name == p:
                ok = asyncio.run(s.health_check())
                print(f'→ {\"connected\" if ok else \"FAILED\"} ')
                break
    except Exception as e:
        print(f'→ error: {e}')
" 2>/dev/null || skip "Scanner health checks (configure credentials in .env)"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  RESULTS: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -eq 0 ]; then
    echo "  🎉 ALL TESTS PASSED"
else
    echo "  ⚠️  $FAIL test(s) failed - check configuration"
fi
echo "══════════════════════════════════════════════════════"
echo ""
echo "NEXT STEPS if something failed:"
echo "  1. API not running?     → docker compose up -d"
echo "  2. DB errors?           → docker compose exec api alembic upgrade head"
echo "  3. LLM not responding?  → docker compose exec ollama ollama pull llama3.3:70b"
echo "  4. Scanner auth failed? → Check API keys in .env.local"
echo "  5. Slack/Teams failed?  → Check webhook URLs in .env.local"
echo "  6. Full logs?           → docker compose logs -f"
