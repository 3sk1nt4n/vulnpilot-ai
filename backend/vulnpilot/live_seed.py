"""
VulnPilot AI - Live Data Seeder
Pulls REAL data from free public APIs, scores through VPRS engine.

NO API keys needed. NO auth. NO config. Just internet access.

Data sources (all free, all public):
  - NVD/NIST: Real CVEs published in the last 7 days
  - EPSS (FIRST.org): Real exploitation probability scores
  - CISA KEV: Real Known Exploited Vulnerabilities catalog
  - abuse.ch ThreatFox: Real malware/exploit indicators

Run: POST /api/v1/live/seed
Or:  python3 -m vulnpilot.live_seed

Takes ~30-60 seconds (rate-limited API calls).
"""

import asyncio
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx

from vulnpilot.scoring.vprs import VPRSEngine
from vulnpilot.scoring.hard_rules import HardRulesEngine
from vulnpilot.threatintel.base import ThreatIntelResult

logger = logging.getLogger(__name__)

# ─── Default asset mapping for demo purposes ───
# In production, this comes from CMDB. For live demo, we simulate
# realistic asset assignments based on CVE product type.
PRODUCT_ASSET_MAP = {
    "firewall": {"tier": "tier_1", "inet": True, "host": "fw-edge-01"},
    "vpn": {"tier": "tier_1", "inet": True, "host": "vpn-gw-01"},
    "web_server": {"tier": "tier_1", "inet": True, "host": "web-prod-01"},
    "database": {"tier": "tier_1", "inet": False, "host": "db-prod-01"},
    "os_server": {"tier": "tier_2", "inet": False, "host": "srv-internal-01"},
    "os_workstation": {"tier": "tier_3", "inet": False, "host": "ws-corp-001"},
    "network_device": {"tier": "tier_2", "inet": True, "host": "switch-core-01"},
    "application": {"tier": "tier_2", "inet": False, "host": "app-internal-01"},
    "default": {"tier": "tier_2", "inet": False, "host": "asset-unknown"},
}


def classify_product(description: str, cpe_products: list[str]) -> str:
    """Classify a CVE into an asset type based on description and CPE."""
    text = (description + " " + " ".join(cpe_products)).lower()
    if any(kw in text for kw in ["firewall", "fortios", "pan-os", "asa", "ftd", "fortigate"]):
        return "firewall"
    if any(kw in text for kw in ["vpn", "connect secure", "pulse", "globalprotect"]):
        return "vpn"
    if any(kw in text for kw in ["apache", "nginx", "iis", "web server", "httpd", "tomcat"]):
        return "web_server"
    if any(kw in text for kw in ["mysql", "postgresql", "oracle", "sql server", "mariadb", "mongodb"]):
        return "database"
    if any(kw in text for kw in ["windows server", "linux", "ubuntu", "rhel", "centos"]):
        return "os_server"
    if any(kw in text for kw in ["windows 10", "windows 11", "macos", "chrome", "firefox", "edge"]):
        return "os_workstation"
    if any(kw in text for kw in ["switch", "router", "cisco ios", "junos"]):
        return "network_device"
    return "default"


async def fetch_recent_cves(days: int = 7, max_results: int = 40) -> list[dict]:
    """Fetch real CVEs from NVD published in the last N days."""
    end = datetime.utcnow()
    start = end - timedelta(days=days)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": min(max_results, 100),
        "startIndex": 0,
    }

    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    cves = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.info(f"Fetching CVEs from NVD (last {days} days)...")
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            total = data.get("totalResults", 0)
            logger.info(f"NVD returned {total} total CVEs, fetching first {max_results}")

            for vuln_item in data.get("vulnerabilities", []):
                cve_data = vuln_item.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue

                # Extract CVSS score
                cvss_score = 0.0
                metrics = cve_data.get("metrics", {})
                for m in metrics.get("cvssMetricV31", []):
                    cvss_score = float(m.get("cvssData", {}).get("baseScore", 0))
                    break
                if cvss_score == 0:
                    for m in metrics.get("cvssMetricV30", []):
                        cvss_score = float(m.get("cvssData", {}).get("baseScore", 0))
                        break
                if cvss_score == 0:
                    for m in metrics.get("cvssMetricV2", []):
                        cvss_score = float(m.get("cvssData", {}).get("baseScore", 0))
                        break

                # Skip CVEs with no CVSS score (reserved/rejected)
                if cvss_score == 0:
                    continue

                # Extract description
                description = ""
                for desc in cve_data.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Extract CWE
                cwe_ids = []
                for weakness in cve_data.get("weaknesses", []):
                    for d in weakness.get("description", []):
                        v = d.get("value", "")
                        if v.startswith("CWE-"):
                            cwe_ids.append(v)

                # Extract CPE products
                cpe_products = []
                for config in cve_data.get("configurations", []):
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe = match.get("criteria", "")
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                cpe_products.append(f"{parts[3]}/{parts[4]}")

                # Check for exploit references
                has_exploit_ref = False
                for ref in cve_data.get("references", []):
                    if "Exploit" in ref.get("tags", []):
                        has_exploit_ref = True
                        break

                published = cve_data.get("published", "")[:10]

                cves.append({
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "description": description[:200],
                    "cwe_ids": cwe_ids,
                    "cpe_products": cpe_products,
                    "has_exploit_ref": has_exploit_ref,
                    "published": published,
                })

    except Exception as e:
        logger.error(f"NVD fetch failed: {e}")

    return cves[:max_results]


async def fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a batch of CVEs. Free, no auth."""
    scores = {}
    if not cve_ids:
        return scores

    # EPSS API supports batch via comma-separated CVE IDs
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Batch in groups of 30
            for i in range(0, len(cve_ids), 30):
                batch = cve_ids[i:i+30]
                cve_param = ",".join(batch)
                logger.info(f"Fetching EPSS for {len(batch)} CVEs...")
                resp = await client.get(
                    "https://api.first.org/data/v1/epss",
                    params={"cve": cve_param},
                )
                if resp.status_code == 200:
                    for item in resp.json().get("data", []):
                        scores[item["cve"]] = float(item.get("epss", 0))
                await asyncio.sleep(1)  # Rate limit courtesy
    except Exception as e:
        logger.warning(f"EPSS batch fetch failed: {e}")

    return scores


async def fetch_kev_catalog() -> set[str]:
    """Download full CISA KEV catalog. Free, no auth."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.info("Downloading CISA KEV catalog...")
            resp = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            resp.raise_for_status()
            catalog = resp.json()
            kev_set = {v["cveID"] for v in catalog.get("vulnerabilities", [])}
            logger.info(f"KEV catalog: {len(kev_set)} CVEs")
            return kev_set
    except Exception as e:
        logger.warning(f"KEV catalog fetch failed: {e}")
        return set()


async def fetch_abusech_iocs(cve_ids: list[str]) -> dict[str, int]:
    """Check abuse.ch ThreatFox for IoCs related to CVEs. Free, no auth."""
    ioc_counts = {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Check a sample (abuse.ch is rate-limited)
            for cve_id in cve_ids[:15]:
                try:
                    resp = await client.post(
                        "https://threatfox-api.abuse.ch/api/v1/",
                        json={"query": "search_term", "search_term": cve_id},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("query_status") == "ok" and data.get("data"):
                            ioc_counts[cve_id] = len(data["data"])
                except Exception:
                    pass
                await asyncio.sleep(0.5)
    except Exception as e:
        logger.warning(f"abuse.ch check failed: {e}")
    return ioc_counts


async def live_seed(weights_path: str = "./config/vprs_weights.yaml",
                    rules_path: str = "./config/hard_rules.yaml",
                    days: int = 7,
                    max_cves: int = 40) -> dict:
    """
    Pull REAL data from free public APIs and score through VPRS engine.

    Pipeline:
      1. NVD → Fetch real CVEs from last N days
      2. EPSS → Fetch real exploitation probabilities
      3. CISA KEV → Check against real known exploited vulns
      4. abuse.ch → Check for real dark web IoCs
      5. VPRS → Score everything through the real engine
      6. Return results for dashboard display
    """
    from vulnpilot.scanners.base import NormalizedVuln

    engine = VPRSEngine(weights_path)
    rules = HardRulesEngine(rules_path)

    # Step 1: Fetch real CVEs from NVD
    raw_cves = await fetch_recent_cves(days=days, max_results=max_cves)
    if not raw_cves:
        return {"error": "Could not fetch CVEs from NVD. Check internet connection.",
                "results": [], "stats": {}}

    cve_ids = [c["cve_id"] for c in raw_cves]

    # Step 2-4: Fetch threat intel in parallel
    epss_task = fetch_epss_batch(cve_ids)
    kev_task = fetch_kev_catalog()
    abuse_task = fetch_abusech_iocs(cve_ids)

    epss_scores, kev_set, abuse_iocs = await asyncio.gather(
        epss_task, kev_task, abuse_task
    )

    # Step 5: Score each CVE through VPRS
    results = []
    stats = {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "noise_eliminated": 0, "tickets_created": 0, "kev_matches": 0,
        "hard_rules_triggered": 0, "flips": 0,
        "data_sources": {
            "nvd_cves_fetched": len(raw_cves),
            "epss_scores_found": len(epss_scores),
            "kev_catalog_size": len(kev_set),
            "abusech_iocs_found": sum(abuse_iocs.values()),
        },
    }

    for cve_data in raw_cves:
        cve_id = cve_data["cve_id"]
        cvss = cve_data["cvss_score"]

        # Classify into asset type
        product_type = classify_product(
            cve_data.get("description", ""),
            cve_data.get("cpe_products", [])
        )
        asset_info = PRODUCT_ASSET_MAP.get(product_type, PRODUCT_ASSET_MAP["default"])

        # Build normalized vuln
        vuln = NormalizedVuln(
            cve_id=cve_id,
            source_scanner="nvd_live",
            cvss_base_score=cvss,
            title=cve_data.get("description", "")[:100],
            hostname=asset_info["host"],
            ip_address="10.0.0.1",
            software=" ".join(cve_data.get("cpe_products", [])[:2]),
            asset_tier=asset_info["tier"],
            is_internet_facing=asset_info["inet"],
        )

        # Build threat intel from REAL API data
        epss = epss_scores.get(cve_id, 0.0)
        in_kev = cve_id in kev_set
        abuse_count = abuse_iocs.get(cve_id, 0)

        intel = ThreatIntelResult(
            cve_id=cve_id,
            epss_score=epss,
            in_kev=in_kev,
            dark_web_mentions=abuse_count,
            exploit_available=cve_data.get("has_exploit_ref", False) or abuse_count > 0,
            exploit_for_sale=False,
            active_scanning=False,
            ransomware_associated=False,
            sources=["nvd", "epss_api", "kev_api", "abusech"],
        )

        # Score through VPRS engine
        vprs_result = engine.calculate_vprs(vuln, intel)
        vprs_result, hard_rule = rules.evaluate(vuln, intel, vprs_result)

        severity = vprs_result.severity.upper()
        is_noise = severity in ("LOW", "INFO")
        is_ticket = severity in ("CRITICAL", "HIGH", "MEDIUM") and vprs_result.vprs_score >= 40

        cvss_sev = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"
        is_flip = (cvss_sev == "CRITICAL" and severity in ("LOW", "INFO")) or \
                  (cvss_sev in ("LOW", "MEDIUM") and severity == "CRITICAL")

        stats["total"] += 1
        stats[severity.lower()] = stats.get(severity.lower(), 0) + 1
        if is_noise: stats["noise_eliminated"] += 1
        if is_ticket: stats["tickets_created"] += 1
        if in_kev: stats["kev_matches"] += 1
        if hard_rule: stats["hard_rules_triggered"] += 1
        if is_flip: stats["flips"] += 1

        results.append({
            "cve_id": cve_id,
            "title": cve_data.get("description", "")[:120],
            "cvss_score": cvss,
            "vprs_score": round(vprs_result.vprs_score, 1),
            "severity": severity,
            "asset_tier": asset_info["tier"],
            "hostname": asset_info["host"],
            "ip_address": "10.0.0.1",
            "is_internet_facing": asset_info["inet"],
            "epss_score": epss,
            "in_kev": in_kev,
            "dark_web_mentions": abuse_count,
            "hard_rule": hard_rule.rule_name if hard_rule else None,
            "is_noise": is_noise,
            "ticket_created": is_ticket,
            "cvss_vs_vprs_flip": is_flip,
            "components": {
                "epss": vprs_result.epss_component,
                "kev": vprs_result.kev_component,
                "dark_web": vprs_result.dark_web_component,
                "asset": vprs_result.asset_component,
                "reachability": vprs_result.reachability_component,
                "controls": vprs_result.controls_component,
            },
            "published": cve_data.get("published", ""),
            "cwe_ids": cve_data.get("cwe_ids", []),
            "cpe_products": cve_data.get("cpe_products", [])[:3],
            "data_source": "LIVE - NVD + EPSS + CISA KEV + abuse.ch",
        })

    results.sort(key=lambda x: x["vprs_score"], reverse=True)
    stats["noise_rate"] = round((stats["noise_eliminated"] / stats["total"]) * 100, 1) if stats["total"] else 0
    stats["seeded_at"] = datetime.utcnow().isoformat()
    stats["mode"] = "LIVE"

    return {"results": results, "stats": stats}


async def main():
    """CLI entry point."""
    print("🌐 Fetching REAL data from public APIs...")
    print("   NVD (CVEs) + EPSS (exploitation probability) + CISA KEV + abuse.ch")
    print("   No API keys needed. This takes 30-60 seconds.\n")

    data = await live_seed()
    stats = data["stats"]
    results = data["results"]

    if not results:
        print("❌ No data fetched. Check your internet connection.")
        return

    ds = stats.get("data_sources", {})
    print(f"╔══════════════════════════════════════════════════════════════╗")
    print(f"║  VulnPilot AI - LIVE Data from Public APIs                  ║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Data Sources:")
    print(f"    NVD CVEs fetched:      {ds.get('nvd_cves_fetched', 0)}")
    print(f"    EPSS scores found:     {ds.get('epss_scores_found', 0)}")
    print(f"    KEV catalog size:      {ds.get('kev_catalog_size', 0)}")
    print(f"    abuse.ch IoCs:         {ds.get('abusech_iocs_found', 0)}")
    print()
    print(f"  VPRS Results:")
    print(f"    Total scored:          {stats['total']}")
    print(f"    Noise eliminated:      {stats['noise_eliminated']} ({stats['noise_rate']}%)")
    print(f"    Tickets would create:  {stats['tickets_created']}")
    print(f"    KEV matches:           {stats['kev_matches']}")
    print(f"    CVSS↔VPRS flips:       {stats['flips']}")
    print()
    print(f"  Top 10 by VPRS:")
    print(f"  {'CVE':<20} {'CVSS':>5} {'VPRS':>6} {'EPSS':>6} {'Sev':<10} {'KEV':>3} {'Published'}")
    print(f"  {'─'*20} {'─'*5} {'─'*6} {'─'*6} {'─'*10} {'─'*3} {'─'*10}")
    for r in results[:10]:
        kev = "YES" if r["in_kev"] else ""
        print(f"  {r['cve_id']:<20} {r['cvss_score']:>5.1f} {r['vprs_score']:>6.1f} {r['epss_score']:>5.1%} {r['severity']:<10} {kev:>3} {r.get('published', '')}")


if __name__ == "__main__":
    asyncio.run(main())
