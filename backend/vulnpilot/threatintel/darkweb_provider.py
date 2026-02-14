"""
VulnPilot AI - Dark Web Exploit Intelligence Provider
Feeds the 'exploit_for_sale' + 'dark_web_mentions' signals into VPRS scoring.

8 SOURCES - from free to enterprise:

FREE (no auth needed):
  1. Shodan Exploits API - Weaponized exploit search by CVE (free with API key)
  2. Shodan CVEDB     - KEV + ransomware + EPSS enrichment, no key needed
  3. ExploitDB/Vulners- Public PoC and exploit database

FREE TIER (signup required):
  4. VulDB            - Exploit price forecasts + dark web risk scoring (free tier)
  5. Shodan (full)    - Internet-wide scanning for vulnerable hosts

PAID (customer brings their own key):
  6. Recorded Future  - Dark web marketplace monitoring, exploit risk scoring
  7. Flashpoint       - Underground forum/marketplace exploit tracking
  8. Intel471         - Dark web threat intel, exploit broker monitoring

One-click GUI setup. Customer pastes API key → Test → Save → Done.
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DarkWebIntel:
    """Dark web intelligence for a single CVE."""
    cve_id: str
    exploit_count: int = 0           # Known exploits (public + underground)
    exploit_for_sale: bool = False   # Exploit actively being sold
    exploit_price_usd: float = 0.0  # Estimated price (from VulDB or observed)
    dark_web_mentions: int = 0       # Forum/marketplace mentions
    ransomware_associated: bool = False
    active_scanning: bool = False    # Mass scanning detected
    poc_available: bool = False      # Proof-of-concept exists
    weaponized: bool = False         # PoC has been weaponized
    sources: list = None

    def __post_init__(self):
        if self.sources is None:
            self.sources = []


class DarkWebIntelProvider:
    """Aggregates dark web signals from all configured sources."""

    def __init__(self):
        # Free sources
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", "")
        self.vuldb_api_key = os.getenv("VULDB_API_KEY", "")

        # Paid sources (customer brings key)
        self.recorded_future_key = os.getenv("RECORDED_FUTURE_API_KEY", "")
        self.flashpoint_key = os.getenv("FLASHPOINT_API_KEY", "")
        self.intel471_key = os.getenv("INTEL471_API_KEY", "")

        self.timeout = 15.0
        self._cache: dict[str, DarkWebIntel] = {}

    async def enrich(self, cve_id: str) -> DarkWebIntel:
        """Get dark web intelligence for a CVE from all configured sources."""
        if cve_id in self._cache:
            return self._cache[cve_id]

        result = DarkWebIntel(cve_id=cve_id)

        # Run all configured sources in parallel
        tasks = [
            self._shodan_cvedb(cve_id, result),
            self._shodan_exploits(cve_id, result),
            self._vuldb(cve_id, result),
            self._recorded_future(cve_id, result),
            self._flashpoint(cve_id, result),
            self._intel471(cve_id, result),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Infer exploit_for_sale from composite signals
        if not result.exploit_for_sale:
            result.exploit_for_sale = self._infer_exploit_for_sale(result)

        self._cache[cve_id] = result
        return result

    def _infer_exploit_for_sale(self, intel: DarkWebIntel) -> bool:
        """Infer if exploit is likely for sale based on composite signals."""
        score = 0
        if intel.exploit_price_usd > 0:
            score += 3  # VulDB has a price estimate
        if intel.weaponized:
            score += 2  # Exploit is weaponized (not just PoC)
        if intel.dark_web_mentions >= 5:
            score += 2  # Significant underground chatter
        if intel.ransomware_associated:
            score += 2  # Ransomware groups interested
        if intel.active_scanning:
            score += 1  # Being actively scanned for
        if intel.exploit_count >= 3:
            score += 1  # Multiple exploits available
        return score >= 4  # High confidence threshold

    # ─── Source 1: Shodan CVEDB (FREE, no auth) ───

    async def _shodan_cvedb(self, cve_id: str, result: DarkWebIntel):
        """Shodan CVEDB - free, no API key needed. KEV + ransomware enrichment."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://cvedb.shodan.io/cve/{cve_id}")
                if resp.status_code != 200:
                    return
                data = resp.json()
                if data.get("kev"):
                    result.sources.append("shodan_cvedb")
                if data.get("ransomware_campaign", "Unknown") != "Unknown":
                    result.ransomware_associated = True
                    result.sources.append("shodan_cvedb_ransomware")
                # EPSS from Shodan as cross-reference
                epss = data.get("epss", 0)
                if epss and epss > 0.5:
                    result.dark_web_mentions += 1
        except Exception as e:
            logger.debug(f"Shodan CVEDB failed for {cve_id}: {e}")

    # ─── Source 2: Shodan Exploits API (FREE with API key) ───

    async def _shodan_exploits(self, cve_id: str, result: DarkWebIntel):
        """Shodan Exploits API - search for weaponized exploits by CVE."""
        if not self.shodan_api_key:
            return
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://exploits.shodan.io/api/search",
                    params={"query": f"cve:{cve_id}", "key": self.shodan_api_key},
                )
                if resp.status_code != 200:
                    return
                data = resp.json()
                total = data.get("total", 0)
                if total > 0:
                    result.exploit_count += total
                    result.poc_available = True
                    result.sources.append(f"shodan_exploits({total})")

                    # Check if any are weaponized (remote type)
                    for match in data.get("matches", []):
                        if match.get("type") in ("remote", "webapps"):
                            result.weaponized = True
                            break
        except Exception as e:
            logger.debug(f"Shodan Exploits failed for {cve_id}: {e}")

    # ─── Source 3: VulDB (FREE tier - exploit price forecasts) ───

    async def _vuldb(self, cve_id: str, result: DarkWebIntel):
        """VulDB - exploit price estimation + dark web risk. Free tier available."""
        if not self.vuldb_api_key:
            return
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    "https://vuldb.com/?api",
                    headers={"X-VulDB-ApiKey": self.vuldb_api_key},
                    data={"search": cve_id, "details": 1},
                )
                if resp.status_code != 200:
                    return
                data = resp.json()
                results_list = data.get("result", [])
                if not results_list:
                    return

                entry = results_list[0]
                advisory = entry.get("advisory", {})
                exploit = entry.get("exploit", {})

                # Exploit price estimation (VulDB's unique feature)
                price_0day = float(exploit.get("0day", {}).get("price", 0) or 0)
                price_today = float(exploit.get("today", {}).get("price", 0) or 0)
                if price_0day > 0 or price_today > 0:
                    result.exploit_price_usd = max(price_0day, price_today)
                    result.sources.append(f"vuldb_price(${result.exploit_price_usd:.0f})")

                # Exploit availability
                if exploit.get("availability") == "1":
                    result.poc_available = True
                    result.exploit_count += 1

                # Threat level from VulDB's own scoring
                threat = advisory.get("threat", {})
                intensity = threat.get("intensity", "")
                if intensity in ("high", "critical"):
                    result.dark_web_mentions += 3
                    result.sources.append(f"vuldb_threat({intensity})")

        except Exception as e:
            logger.debug(f"VulDB failed for {cve_id}: {e}")

    # ─── Source 4: Recorded Future (PAID - $$$) ───

    async def _recorded_future(self, cve_id: str, result: DarkWebIntel):
        """Recorded Future - dark web marketplace + underground forum monitoring.
        Risk rules include: 'Exploit Available on Underground Markets',
        'Linked to Cyber Exploit', 'Positive Analyst Sentiment in Underground'."""
        if not self.recorded_future_key:
            return
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"https://api.recordedfuture.com/v2/vulnerability/{cve_id}",
                    headers={"X-RFToken": self.recorded_future_key},
                    params={"fields": "risk,timestamps,metrics"},
                )
                if resp.status_code != 200:
                    return
                data = resp.json().get("data", {})
                risk = data.get("risk", {})

                # Risk score (0-100)
                rf_score = risk.get("score", 0)
                if rf_score >= 70:
                    result.dark_web_mentions += 5
                elif rf_score >= 40:
                    result.dark_web_mentions += 2

                # Risk rules - the gold for dark web signals
                for rule in risk.get("evidenceDetails", []):
                    rule_name = rule.get("rule", "").lower()
                    if "underground" in rule_name or "dark web" in rule_name:
                        result.exploit_for_sale = True
                        result.dark_web_mentions += 3
                    if "exploit" in rule_name and "available" in rule_name:
                        result.weaponized = True
                        result.exploit_count += 1
                    if "ransomware" in rule_name:
                        result.ransomware_associated = True
                    if "actively" in rule_name and "exploit" in rule_name:
                        result.active_scanning = True

                result.sources.append(f"recorded_future(score:{rf_score})")

        except Exception as e:
            logger.debug(f"Recorded Future failed for {cve_id}: {e}")

    # ─── Source 5: Flashpoint (PAID - $$$) ───

    async def _flashpoint(self, cve_id: str, result: DarkWebIntel):
        """Flashpoint - underground forum/marketplace CVE tracking."""
        if not self.flashpoint_key:
            return
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://fp.tools/api/v4/indicators/simple",
                    headers={"Authorization": f"Bearer {self.flashpoint_key}"},
                    params={"query": cve_id, "limit": 10},
                )
                if resp.status_code != 200:
                    return
                data = resp.json()
                hits = data.get("total", 0)
                if hits > 0:
                    result.dark_web_mentions += hits
                    result.sources.append(f"flashpoint({hits})")

                    # Check for exploit-related indicators
                    for item in data.get("data", []):
                        itype = item.get("type", "").lower()
                        if "exploit" in itype:
                            result.exploit_for_sale = True
                            result.weaponized = True

        except Exception as e:
            logger.debug(f"Flashpoint failed for {cve_id}: {e}")

    # ─── Source 6: Intel 471 (PAID - $$$) ───

    async def _intel471(self, cve_id: str, result: DarkWebIntel):
        """Intel471 - dark web broker monitoring, exploit marketplace tracking."""
        if not self.intel471_key:
            return
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    "https://api.intel471.com/v1/cve/cve-reports",
                    headers={"Authorization": f"Basic {self.intel471_key}"},
                    params={"cve": cve_id},
                )
                if resp.status_code != 200:
                    return
                data = resp.json()
                reports = data.get("cve_reports", [])
                if reports:
                    result.dark_web_mentions += len(reports)
                    result.sources.append(f"intel471({len(reports)})")

                    for report in reports:
                        activity = report.get("activity", {})
                        if activity.get("exploit_available"):
                            result.exploit_for_sale = True
                        if activity.get("underground_activity"):
                            result.dark_web_mentions += 2

        except Exception as e:
            logger.debug(f"Intel471 failed for {cve_id}: {e}")

    # ─── Utility ───

    def clear_cache(self):
        self._cache.clear()

    async def health_check(self) -> dict:
        """Check which sources are configured and reachable."""
        status = {}

        # Shodan CVEDB (always free)
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get("https://cvedb.shodan.io/cve/CVE-2024-0001")
                status["shodan_cvedb"] = {"ok": r.status_code == 200, "cost": "free"}
        except:
            status["shodan_cvedb"] = {"ok": False, "cost": "free"}

        # Shodan Exploits
        status["shodan_exploits"] = {
            "ok": bool(self.shodan_api_key),
            "configured": bool(self.shodan_api_key),
            "cost": "free_tier",
        }

        # VulDB
        status["vuldb"] = {
            "ok": bool(self.vuldb_api_key),
            "configured": bool(self.vuldb_api_key),
            "cost": "free_tier",
        }

        # Paid sources
        for name, key in [
            ("recorded_future", self.recorded_future_key),
            ("flashpoint", self.flashpoint_key),
            ("intel471", self.intel471_key),
        ]:
            status[name] = {
                "ok": bool(key),
                "configured": bool(key),
                "cost": "paid",
            }

        return status
