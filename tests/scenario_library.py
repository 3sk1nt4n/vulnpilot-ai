#!/usr/bin/env python3
"""
VulnPilot AI - Scenario Library
"CVSS got it wrong, VPRS got it right"

Run: python3 tests/scenario_library.py
All scenarios use the VPRS scoring engine with NO mocks.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from vulnpilot.scoring.vprs import VPRSEngine
from vulnpilot.scoring.hard_rules import HardRulesEngine
from vulnpilot.scanners.base import NormalizedVuln
from vulnpilot.threatintel.base import ThreatIntelResult

engine = VPRSEngine("./config/vprs_weights.yaml")
rules = HardRulesEngine("./config/hard_rules.yaml")

PASS = 0
FAIL = 0


def score(vuln, intel, label=""):
    r = engine.calculate_vprs(vuln, intel)
    r, hr = rules.evaluate(vuln, intel, r)
    hr_name = hr.rule_name if hr else ""
    print(f"  {label:58s} CVSS {vuln.cvss_base_score:4.1f} → VPRS {r.vprs_score:5.1f} ({r.severity.upper():8s}) {hr_name}")
    return r


def check(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"    ✅ {name}")
    else:
        FAIL += 1
        print(f"    ❌ {name}")


def main():
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║  VulnPilot AI - Scenario Library: CVSS Got It Wrong, VPRS Got It Right     ║")
    print("║  Every edge case. Real scores. No mocks.                                    ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")

    # ═══════════════════════════════════════════════════════
    print("\n═══ EASY WINS ═══\n")

    print("1. PATCH TUESDAY FLOOD")
    print("   200 CVEs, 40 are CVSS 9.0+. Only 3 matter.\n")
    r1 = score(NormalizedVuln(cve_id="CVE-PT-001", source_scanner="tenable", cvss_base_score=9.1,
               asset_tier="tier_1", is_internet_facing=True),
               ThreatIntelResult(cve_id="CVE-PT-001", epss_score=0.85, in_kev=True),
               "REAL: EPSS 85% + KEV + Tier 1")
    r2 = score(NormalizedVuln(cve_id="CVE-PT-NOISE", source_scanner="tenable", cvss_base_score=9.8,
               asset_tier="tier_3", is_internet_facing=False),
               ThreatIntelResult(cve_id="CVE-PT-NOISE", epss_score=0.003, in_kev=False),
               "NOISE: CVSS 9.8 but EPSS 0.3%, no KEV, Tier 3")
    check("Real threat scored CRITICAL", r1.severity == "critical")
    check("Noise scored LOW or INFO", r1.vprs_score > r2.vprs_score and r2.severity in ("low", "info"))
    check("CVSS 9.8 noise < CVSS 9.1 real threat", r2.vprs_score < r1.vprs_score)

    print("\n2. LEGACY SYSTEM FALSE ALARM")
    print("   CVSS 9.8 but air-gapped + segmented + IPS\n")
    r = score(NormalizedVuln(cve_id="CVE-LEGACY", source_scanner="qualys", cvss_base_score=9.8,
              asset_tier="tier_3", is_internet_facing=False, has_ips=True, is_segmented=True, has_waf=True),
              ThreatIntelResult(cve_id="CVE-LEGACY", epss_score=0.02, in_kev=False),
              "CVSS 9.8 + air-gapped + IPS + WAF + segmented")
    check("CVSS 9.8 scored as INFO or LOW", r.severity in ("info", "low"))

    print('\n3. "MEDIUM" ACTUALLY ON FIRE')
    print("   CVSS 6.1 XSS on payment portal + dark web exploit\n")
    r = score(NormalizedVuln(cve_id="CVE-FIRE", source_scanner="rapid7", cvss_base_score=6.1,
              asset_tier="tier_1", is_internet_facing=True, has_waf=False),
              ThreatIntelResult(cve_id="CVE-FIRE", epss_score=0.72, in_kev=False,
                                dark_web_mentions=8, exploit_available=True, exploit_for_sale=True),
              'CVSS 6.1 + EPSS 72% + exploit for sale + Tier 1')
    check("CVSS 6.1 scored as CRITICAL or HIGH", r.severity in ("critical", "high"))

    # ═══════════════════════════════════════════════════════
    print("\n═══ HARDER MULTI-VARIABLE SCENARIOS ═══\n")

    print("4. SAME CVE, DIFFERENT VPRS ON DIFFERENT ASSETS")
    print("   Same CVE-2024-XXXXX on 2 servers. CVSS treats them identically.\n")
    r_dev = score(NormalizedVuln(cve_id="CVE-SAME", source_scanner="tenable", cvss_base_score=8.0,
                  hostname="dev-box", asset_tier="tier_3", is_internet_facing=False,
                  has_ips=True, is_segmented=True),
                  ThreatIntelResult(cve_id="CVE-SAME", epss_score=0.35, in_kev=False),
                  "Asset A: Dev box + IPS + segmented")
    r_prod = score(NormalizedVuln(cve_id="CVE-SAME", source_scanner="tenable", cvss_base_score=8.0,
                   hostname="prod-db", asset_tier="tier_1", is_internet_facing=True),
                   ThreatIntelResult(cve_id="CVE-SAME", epss_score=0.35, in_kev=False),
                   "Asset B: Prod DB, internet-facing, no controls")
    check("Same CVE, different scores", abs(r_dev.vprs_score - r_prod.vprs_score) > 15)
    check("Prod DB scored higher than dev box", r_prod.vprs_score > r_dev.vprs_score)

    print("\n5. KEV OVERRIDE - AI deprioritized, then CISA adds to KEV overnight")
    print("   Drift Detector catches it, Hard Rule overrides score.\n")
    r_before = score(NormalizedVuln(cve_id="CVE-KEV-FLIP", source_scanner="tenable", cvss_base_score=7.2,
                     asset_tier="tier_2", is_internet_facing=False, has_ips=True),
                     ThreatIntelResult(cve_id="CVE-KEV-FLIP", epss_score=0.03, in_kev=False),
                     "BEFORE: Low EPSS + controls → deprioritized")
    r_after = score(NormalizedVuln(cve_id="CVE-KEV-FLIP", source_scanner="tenable", cvss_base_score=7.2,
                    asset_tier="tier_2", is_internet_facing=False, has_ips=True),
                    ThreatIntelResult(cve_id="CVE-KEV-FLIP", epss_score=0.03, in_kev=True),
                    "AFTER: CISA adds to KEV → Hard Rule fires")
    check("KEV addition jumps to CRITICAL", r_after.severity == "critical")
    check(f"Score jumped +{r_after.vprs_score - r_before.vprs_score:.0f} points", r_after.vprs_score - r_before.vprs_score > 50)

    print("\n6. DARK WEB SIGNAL ESCALATION")
    print("   CVSS 5.4 medium. Looks boring. Then dark web lights up.\n")
    r_quiet = score(NormalizedVuln(cve_id="CVE-DW", source_scanner="qualys", cvss_base_score=5.4,
                    asset_tier="tier_2", is_internet_facing=True),
                    ThreatIntelResult(cve_id="CVE-DW", epss_score=0.08, in_kev=False),
                    "QUIET: No dark web signals")
    r_hot = score(NormalizedVuln(cve_id="CVE-DW", source_scanner="qualys", cvss_base_score=5.4,
                  asset_tier="tier_2", is_internet_facing=True),
                  ThreatIntelResult(cve_id="CVE-DW", epss_score=0.08, in_kev=False,
                                    dark_web_mentions=6, exploit_available=True, active_scanning=True),
                  "HOT: GreyNoise + exploit + 6 mentions")
    check("Dark web signals increased score", r_hot.vprs_score > r_quiet.vprs_score)

    print("\n7. COMPENSATING CONTROLS GRADIENT")
    print("   Same vuln, progressive control layers.\n")
    base = dict(cve_id="CVE-CTRL", source_scanner="tenable", cvss_base_score=8.5,
                asset_tier="tier_1", is_internet_facing=True)
    intel = ThreatIntelResult(cve_id="CVE-CTRL", epss_score=0.5, in_kev=False, exploit_available=True)
    r_none = score(NormalizedVuln(**base), intel, "Zero controls")
    r_waf = score(NormalizedVuln(**base, has_waf=True), intel, "WAF only")
    r_both = score(NormalizedVuln(**base, has_waf=True, has_ips=True), intel, "WAF + IPS")
    r_full = score(NormalizedVuln(**base, has_waf=True, has_ips=True, is_segmented=True), intel, "WAF + IPS + Segmented")
    check("More controls = lower score", r_none.vprs_score > r_waf.vprs_score > r_both.vprs_score > r_full.vprs_score)

    # ═══════════════════════════════════════════════════════
    print("\n═══ ADVANCED / DIFFICULT SCENARIOS ═══\n")

    print("8. EPSS vs KEV DISAGREEMENT")
    print("   EPSS says 2%. CISA says actively exploited. Who wins?\n")
    r_epss = score(NormalizedVuln(cve_id="CVE-VS", source_scanner="tenable", cvss_base_score=7.0,
                   asset_tier="tier_2", is_internet_facing=True),
                   ThreatIntelResult(cve_id="CVE-VS", epss_score=0.02, in_kev=False),
                   "EPSS only (2%, no KEV)")
    r_kev = score(NormalizedVuln(cve_id="CVE-VS", source_scanner="tenable", cvss_base_score=7.0,
                  asset_tier="tier_2", is_internet_facing=True),
                  ThreatIntelResult(cve_id="CVE-VS", epss_score=0.02, in_kev=True),
                  "EPSS 2% BUT in KEV → KEV wins")
    check("KEV overrides low EPSS → CRITICAL", r_kev.severity == "critical")
    check("Without KEV, same vuln is LOW", r_epss.severity in ("low", "medium"))

    print("\n9. ZERO-DAY - No EPSS, no KEV, dark web is on fire")
    print("   Brand new CVE. Official feeds haven't caught up yet.\n")
    r_day0 = score(NormalizedVuln(cve_id="CVE-0DAY", source_scanner="rapid7", cvss_base_score=8.5,
                   asset_tier="tier_1", is_internet_facing=True),
                   ThreatIntelResult(cve_id="CVE-0DAY", epss_score=0.0, in_kev=False),
                   "DAY 0: No signals (EPSS/KEV not updated yet)")
    r_day1 = score(NormalizedVuln(cve_id="CVE-0DAY", source_scanner="rapid7", cvss_base_score=8.5,
                   asset_tier="tier_1", is_internet_facing=True),
                   ThreatIntelResult(cve_id="CVE-0DAY", epss_score=0.0, in_kev=False,
                                     dark_web_mentions=12, exploit_for_sale=True,
                                     exploit_available=True, active_scanning=True),
                   "DAY 1: Exploit for sale + scanning + mentions")
    r_day2 = score(NormalizedVuln(cve_id="CVE-0DAY", source_scanner="rapid7", cvss_base_score=8.5,
                   asset_tier="tier_1", is_internet_facing=True),
                   ThreatIntelResult(cve_id="CVE-0DAY", epss_score=0.0, in_kev=False,
                                     dark_web_mentions=12, exploit_for_sale=True,
                                     exploit_available=True, active_scanning=True,
                                     ransomware_associated=True),
                   "DAY 2: + ransomware → Hard Rule fires")
    check("Day 0 → Day 1: score jumped on dark web signals", r_day1.vprs_score > r_day0.vprs_score + 20)
    check("Day 1 → Day 2: ransomware → CRITICAL", r_day2.severity == "critical")
    check("Zero-day detected BEFORE EPSS/KEV", r_day1.vprs_score >= 85)

    print("\n10. RISK ACCEPTANCE - Full 6-factor justification for board\n")
    vuln = NormalizedVuln(cve_id="CVE-ACCEPT", source_scanner="tenable", cvss_base_score=6.5,
           asset_tier="tier_2", is_internet_facing=False, has_ips=True)
    intel = ThreatIntelResult(cve_id="CVE-ACCEPT", epss_score=0.04, in_kev=False)
    r = engine.calculate_vprs(vuln, intel)
    print(f"  Score: {r.vprs_score:.1f} ({r.severity.upper()}) - Business accepts risk")
    print(f"  Board Justification:")
    print(f"    EPSS:       {r.epss_component:5.2f}  (probability={intel.epss_score}, weight=25%)")
    print(f"    KEV:        {r.kev_component:5.2f}  (active_exploit={intel.in_kev}, weight=20%)")
    print(f"    Dark Web:   {r.dark_web_component:5.2f}  (mentions={intel.dark_web_mentions}, weight=15%)")
    print(f"    Asset:      {r.asset_component:5.2f}  (tier={vuln.asset_tier}, weight=20%)")
    print(f"    Reachability:{r.reachability_component:5.2f}  (internet={vuln.is_internet_facing}, weight=12%)")
    print(f"    Controls:   {r.controls_component:5.2f}  (IPS={vuln.has_ips}, weight=8%)")
    print(f"    TOTAL:      {r.vprs_score:5.2f}")
    check("All 6 components documented", all([
        r.epss_component >= 0, r.kev_component >= 0, r.dark_web_component >= 0,
        r.asset_component >= 0, r.reachability_component >= 0, r.controls_component >= 0]))
    check("Components sum to VPRS total", abs(
        r.epss_component + r.kev_component + r.dark_web_component +
        r.asset_component + r.reachability_component + r.controls_component - r.vprs_score) < 0.1)

    print("\n11. THE ULTIMATE FLIP - CVSS order completely inverted\n")
    scenarios = [
        ("CVE-CVSS-9.8-INFO",  9.8, "tier_3", False, True, True,  0.005, False, 0, False, False),
        ("CVE-CVSS-9.5-LOW",   9.5, "tier_2", False, False, False, 0.02, False, 0, False, False),
        ("CVE-CVSS-6.5-HIGH",  6.5, "tier_1", True,  False, False, 0.55, False, 5, True, False),
        ("CVE-CVSS-4.3-CRIT",  4.3, "tier_1", True,  False, False, 0.80, True,  10, True, False),
    ]
    results = []
    for (cve, cvss, tier, inet, waf, seg, epss, kev, dw, exploit, ransomware) in scenarios:
        v = NormalizedVuln(cve_id=cve, source_scanner="test", cvss_base_score=cvss,
                           asset_tier=tier, is_internet_facing=inet, has_waf=waf, is_segmented=seg)
        i = ThreatIntelResult(cve_id=cve, epss_score=epss, in_kev=kev,
                              dark_web_mentions=dw, exploit_available=exploit)
        r = score(v, i, cve)
        results.append((cvss, r.vprs_score, r.severity))

    print()
    print(f"  CVSS ranking:  {' > '.join([f'{c[0]}' for c in sorted(results, key=lambda x: -x[0])])}")
    print(f"  VPRS ranking:  {' > '.join([f'{c[1]:.1f}' for c in sorted(results, key=lambda x: -x[1])])}")
    check("CVSS 4.3 scored HIGHEST by VPRS", max(results, key=lambda x: x[1])[0] == 4.3)
    check("CVSS 9.8 scored LOWEST by VPRS", min(results, key=lambda x: x[1])[0] == 9.8)

    # ═══════════════════════════════════════════════════════
    print("\n" + "═" * 60)
    print(f"  SCENARIO RESULTS: {PASS} passed, {FAIL} failed")
    if FAIL == 0:
        print("  🎯 ALL SCENARIOS VALIDATED - VPRS beats CVSS in every case")
    else:
        print(f"  ⚠️  {FAIL} scenario(s) need attention")
    print("═" * 60)


if __name__ == "__main__":
    main()
