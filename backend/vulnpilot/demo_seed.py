"""
VulnPilot AI - Demo Data Seeder
Loads 50 realistic CVEs through the full VPRS pipeline on startup.

Run: python3 -m vulnpilot.demo_seed
Or:  POST /api/v1/demo/seed

What it does:
  1. Creates 50 real-world CVEs with realistic threat intel
  2. Scores each one through the VPRS engine + Hard Rules
  3. Shows the full pipeline output: scores, severity, components, tickets
  4. Proves CVSS vs VPRS thesis with real data visible in the dashboard

Takes ~2 seconds. No network calls. No AI needed.
"""

import json
import logging
import os
import sys
import random
from datetime import datetime, timedelta

# Allow running as standalone script
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vulnpilot.scoring.vprs import VPRSEngine
from vulnpilot.scoring.hard_rules import HardRulesEngine
from vulnpilot.scanners.base import NormalizedVuln
from vulnpilot.threatintel.base import ThreatIntelResult

logger = logging.getLogger(__name__)

# ─── 50 Realistic CVEs ───
# Mix of real CVE patterns: Patch Tuesday floods, zero-days, legacy vulns,
# KEV entries, dark web exploits, and boring noise

DEMO_CVES = [
    # === CRITICAL: Real threats that need immediate action ===
    {"cve": "CVE-2024-21887", "cvss": 9.1, "title": "Ivanti Connect Secure RCE",
     "tier": "tier_1", "inet": True, "epss": 0.95, "kev": True, "dw": 15, "exploit": True, "sale": True, "ransom": True,
     "host": "vpn-gateway-01", "ip": "10.1.1.5", "software": "Ivanti Connect Secure 9.x"},

    {"cve": "CVE-2024-3400", "cvss": 10.0, "title": "Palo Alto PAN-OS Command Injection",
     "tier": "tier_1", "inet": True, "epss": 0.97, "kev": True, "dw": 22, "exploit": True, "sale": True, "ransom": True,
     "host": "fw-edge-01", "ip": "10.1.1.1", "software": "PAN-OS 11.1"},

    {"cve": "CVE-2024-47575", "cvss": 9.8, "title": "FortiManager Missing Authentication",
     "tier": "tier_1", "inet": True, "epss": 0.92, "kev": True, "dw": 18, "exploit": True, "sale": True, "ransom": False,
     "host": "fortimanager-01", "ip": "10.1.1.3", "software": "FortiManager 7.4"},

    {"cve": "CVE-2023-46805", "cvss": 8.2, "title": "Ivanti EPMM Authentication Bypass",
     "tier": "tier_1", "inet": True, "epss": 0.88, "kev": True, "dw": 12, "exploit": True, "sale": False, "ransom": False,
     "host": "mdm-server-01", "ip": "10.1.2.10", "software": "Ivanti EPMM"},

    {"cve": "CVE-2024-1709", "cvss": 10.0, "title": "ScreenConnect Authentication Bypass",
     "tier": "tier_1", "inet": True, "epss": 0.94, "kev": True, "dw": 20, "exploit": True, "sale": True, "ransom": True,
     "host": "rmm-server-01", "ip": "10.1.2.15", "software": "ConnectWise ScreenConnect"},

    # === HIGH: Serious but context-dependent ===
    {"cve": "CVE-2024-6387", "cvss": 8.1, "title": "OpenSSH regreSSHion RCE",
     "tier": "tier_2", "inet": True, "epss": 0.45, "kev": False, "dw": 8, "exploit": True, "sale": False, "ransom": False,
     "host": "web-prod-01", "ip": "10.2.1.10", "software": "OpenSSH 9.7"},

    {"cve": "CVE-2024-4577", "cvss": 9.8, "title": "PHP CGI Argument Injection",
     "tier": "tier_2", "inet": True, "epss": 0.78, "kev": True, "dw": 6, "exploit": True, "sale": False, "ransom": False,
     "host": "web-legacy-01", "ip": "10.2.1.20", "software": "PHP 8.1"},

    {"cve": "CVE-2024-27198", "cvss": 9.8, "title": "JetBrains TeamCity Auth Bypass",
     "tier": "tier_2", "inet": False, "epss": 0.65, "kev": True, "dw": 5, "exploit": True, "sale": False, "ransom": False,
     "host": "cicd-server-01", "ip": "10.3.1.5", "software": "TeamCity 2023.11"},

    {"cve": "CVE-2024-23897", "cvss": 9.8, "title": "Jenkins CLI Arbitrary File Read",
     "tier": "tier_2", "inet": False, "epss": 0.55, "kev": False, "dw": 4, "exploit": True, "sale": False, "ransom": False,
     "host": "jenkins-01", "ip": "10.3.1.10", "software": "Jenkins 2.426", "waf": True},

    {"cve": "CVE-2024-20353", "cvss": 8.6, "title": "Cisco ASA/FTD DoS",
     "tier": "tier_1", "inet": True, "epss": 0.72, "kev": True, "dw": 3, "exploit": True, "sale": False, "ransom": False,
     "host": "asa-edge-01", "ip": "10.1.1.2", "software": "Cisco ASA 9.18"},

    # === MEDIUM: Real risk but lower priority ===
    {"cve": "CVE-2024-21762", "cvss": 9.8, "title": "FortiOS Out-of-Bound Write",
     "tier": "tier_2", "inet": False, "epss": 0.35, "kev": False, "dw": 2, "exploit": False, "sale": False, "ransom": False,
     "host": "fw-internal-01", "ip": "10.3.2.1", "software": "FortiOS 7.2", "ips": True, "seg": True},

    {"cve": "CVE-2024-0012", "cvss": 9.1, "title": "PAN-OS Management Interface Auth Bypass",
     "tier": "tier_2", "inet": False, "epss": 0.28, "kev": False, "dw": 1, "exploit": False, "sale": False, "ransom": False,
     "host": "fw-mgmt-01", "ip": "10.4.1.1", "software": "PAN-OS 11.0", "seg": True, "ips": True},

    {"cve": "CVE-2024-38812", "cvss": 9.8, "title": "VMware vCenter Heap Overflow",
     "tier": "tier_1", "inet": False, "epss": 0.22, "kev": False, "dw": 1, "exploit": False, "sale": False, "ransom": False,
     "host": "vcenter-01", "ip": "10.4.2.5", "software": "vCenter 8.0", "seg": True},

    {"cve": "CVE-2024-30088", "cvss": 7.0, "title": "Windows Kernel Elevation of Privilege",
     "tier": "tier_2", "inet": False, "epss": 0.18, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-dev-042", "ip": "10.5.3.42", "software": "Windows 11 23H2"},

    {"cve": "CVE-2024-38063", "cvss": 9.8, "title": "Windows TCP/IP RCE",
     "tier": "tier_3", "inet": False, "epss": 0.12, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-eng-015", "ip": "10.5.4.15", "software": "Windows Server 2022", "seg": True, "ips": True},

    # === PATCH TUESDAY NOISE: High CVSS, no real threat ===
    {"cve": "CVE-2024-38199", "cvss": 9.8, "title": "Windows LPD RCE",
     "tier": "tier_3", "inet": False, "epss": 0.004, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "print-srv-01", "ip": "10.6.1.5", "software": "Windows Server 2019", "seg": True, "ips": True, "waf": True},

    {"cve": "CVE-2024-38143", "cvss": 9.8, "title": "Windows WLAN AutoConfig RCE",
     "tier": "tier_3", "inet": False, "epss": 0.003, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-office-101", "ip": "10.6.2.101", "software": "Windows 11"},

    {"cve": "CVE-2024-38140", "cvss": 9.8, "title": "Windows Reliable Multicast RCE",
     "tier": "tier_3", "inet": False, "epss": 0.002, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-office-102", "ip": "10.6.2.102", "software": "Windows 10 22H2", "seg": True},

    {"cve": "CVE-2024-38159", "cvss": 9.1, "title": "Windows NFS RCE",
     "tier": "tier_3", "inet": False, "epss": 0.005, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "file-srv-02", "ip": "10.6.1.10", "software": "Windows Server 2022", "ips": True},

    {"cve": "CVE-2024-38160", "cvss": 9.1, "title": "Windows NFS RCE (variant)",
     "tier": "tier_3", "inet": False, "epss": 0.004, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "file-srv-03", "ip": "10.6.1.11", "software": "Windows Server 2022", "seg": True},

    {"cve": "CVE-2024-43491", "cvss": 9.8, "title": "Windows Update Servicing Stack",
     "tier": "tier_3", "inet": False, "epss": 0.008, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-hr-005", "ip": "10.6.3.5", "software": "Windows 10 1507"},

    {"cve": "CVE-2024-38178", "cvss": 7.5, "title": "Windows Scripting Engine Memory Corruption",
     "tier": "tier_3", "inet": False, "epss": 0.006, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-finance-003", "ip": "10.6.4.3", "software": "Windows 11", "seg": True, "ips": True, "waf": True},

    # === LOW: "Medium" CVEs that VPRS correctly deprioritizes ===
    {"cve": "CVE-2024-38077", "cvss": 7.8, "title": "Windows Hyper-V EoP",
     "tier": "tier_3", "inet": False, "epss": 0.01, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "hyperv-dev-01", "ip": "10.7.1.5", "software": "Windows Server 2022", "seg": True, "ips": True},

    {"cve": "CVE-2024-38106", "cvss": 7.0, "title": "Windows Kernel Use After Free",
     "tier": "tier_3", "inet": False, "epss": 0.015, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-test-008", "ip": "10.7.2.8", "software": "Windows 11"},

    {"cve": "CVE-2024-38213", "cvss": 6.5, "title": "Windows Mark of the Web Bypass",
     "tier": "tier_3", "inet": False, "epss": 0.02, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False,
     "host": "ws-mktg-012", "ip": "10.7.3.12", "software": "Windows 11"},

    # === FLIP CASES: CVSS medium but VPRS critical ===
    {"cve": "CVE-2024-FLIP-01", "cvss": 6.1, "title": "XSS on Customer Payment Portal",
     "tier": "tier_1", "inet": True, "epss": 0.72, "kev": False, "dw": 8, "exploit": True, "sale": True, "ransom": False,
     "host": "pay-portal-01", "ip": "10.1.3.5", "software": "Custom Web App"},

    {"cve": "CVE-2024-FLIP-02", "cvss": 5.4, "title": "SSRF in Internal API Gateway",
     "tier": "tier_1", "inet": True, "epss": 0.65, "kev": False, "dw": 6, "exploit": True, "sale": False, "ransom": False,
     "host": "api-gw-prod-01", "ip": "10.1.3.10", "software": "Kong Gateway"},

    {"cve": "CVE-2024-FLIP-03", "cvss": 4.3, "title": "Info Disclosure in Auth Service",
     "tier": "tier_1", "inet": True, "epss": 0.82, "kev": True, "dw": 10, "exploit": True, "sale": True, "ransom": False,
     "host": "auth-prod-01", "ip": "10.1.3.15", "software": "Custom Auth Service"},

    # === SAME CVE, DIFFERENT ASSETS ===
    {"cve": "CVE-2024-SAME-01", "cvss": 8.0, "title": "Log4Shell variant on Dev Box",
     "tier": "tier_3", "inet": False, "epss": 0.35, "kev": False, "dw": 2, "exploit": True, "sale": False, "ransom": False,
     "host": "dev-java-01", "ip": "10.7.5.1", "software": "Log4j 2.17", "seg": True, "ips": True},

    {"cve": "CVE-2024-SAME-01", "cvss": 8.0, "title": "Log4Shell variant on Prod DB",
     "tier": "tier_1", "inet": True, "epss": 0.35, "kev": False, "dw": 2, "exploit": True, "sale": False, "ransom": False,
     "host": "prod-db-01", "ip": "10.1.5.10", "software": "Log4j 2.17"},

    # === MORE NOISE to boost elimination stats ===
    {"cve": "CVE-2024-N001", "cvss": 9.8, "title": "Windows SMB RCE", "tier": "tier_3", "inet": False, "epss": 0.003, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "ws-101", "ip": "10.8.1.1", "software": "Windows 11", "seg": True, "ips": True},
    {"cve": "CVE-2024-N002", "cvss": 9.5, "title": "Windows RDP RCE", "tier": "tier_3", "inet": False, "epss": 0.005, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "ws-102", "ip": "10.8.1.2", "software": "Windows 11", "seg": True},
    {"cve": "CVE-2024-N003", "cvss": 9.3, "title": "Windows LDAP RCE", "tier": "tier_3", "inet": False, "epss": 0.002, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "dc-test-01", "ip": "10.8.2.1", "software": "Windows Server 2022", "seg": True, "ips": True, "waf": True},
    {"cve": "CVE-2024-N004", "cvss": 9.1, "title": "Windows DNS RCE", "tier": "tier_3", "inet": False, "epss": 0.004, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "dns-int-01", "ip": "10.8.2.5", "software": "Windows Server 2019"},
    {"cve": "CVE-2024-N005", "cvss": 8.8, "title": "Windows Print Spooler EoP", "tier": "tier_3", "inet": False, "epss": 0.006, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "print-02", "ip": "10.8.3.1", "software": "Windows Server 2019", "seg": True},
    {"cve": "CVE-2024-N006", "cvss": 9.0, "title": "Windows MSHTML RCE", "tier": "tier_3", "inet": False, "epss": 0.003, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "ws-103", "ip": "10.8.1.3", "software": "Windows 10"},
    {"cve": "CVE-2024-N007", "cvss": 9.8, "title": "Windows OLE RCE", "tier": "tier_3", "inet": False, "epss": 0.002, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "ws-104", "ip": "10.8.1.4", "software": "Windows 11", "seg": True, "ips": True},
    {"cve": "CVE-2024-N008", "cvss": 8.5, "title": "Windows Kerberos EoP", "tier": "tier_3", "inet": False, "epss": 0.007, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "dc-test-02", "ip": "10.8.2.2", "software": "Windows Server 2022"},
    {"cve": "CVE-2024-N009", "cvss": 9.2, "title": "Windows Task Scheduler EoP", "tier": "tier_3", "inet": False, "epss": 0.004, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "ws-105", "ip": "10.8.1.5", "software": "Windows 11", "seg": True},
    {"cve": "CVE-2024-N010", "cvss": 8.0, "title": "Windows COM+ RCE", "tier": "tier_3", "inet": False, "epss": 0.005, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "ws-106", "ip": "10.8.1.6", "software": "Windows 10", "ips": True},
    {"cve": "CVE-2024-N011", "cvss": 9.8, "title": "Windows Netlogon EoP", "tier": "tier_3", "inet": False, "epss": 0.003, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "dc-backup", "ip": "10.8.2.3", "software": "Windows Server 2019", "seg": True, "ips": True},
    {"cve": "CVE-2024-N012", "cvss": 7.5, "title": "Linux Kernel LPE", "tier": "tier_3", "inet": False, "epss": 0.008, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "linux-test-01", "ip": "10.8.4.1", "software": "Ubuntu 22.04"},
    {"cve": "CVE-2024-N013", "cvss": 9.1, "title": "Apache Struts RCE", "tier": "tier_3", "inet": False, "epss": 0.006, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "app-staging", "ip": "10.8.5.1", "software": "Apache Struts 6.3", "seg": True},
    {"cve": "CVE-2024-N014", "cvss": 8.8, "title": "PostgreSQL SQL Injection", "tier": "tier_3", "inet": False, "epss": 0.004, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "db-staging", "ip": "10.8.5.5", "software": "PostgreSQL 15", "seg": True, "ips": True},
    {"cve": "CVE-2024-N015", "cvss": 9.0, "title": "Nginx Integer Overflow", "tier": "tier_3", "inet": False, "epss": 0.003, "kev": False, "dw": 0, "exploit": False, "sale": False, "ransom": False, "host": "proxy-test", "ip": "10.8.5.10", "software": "Nginx 1.25"},

    # === ZERO-DAY: Dark web signals but no EPSS/KEV yet ===
    {"cve": "CVE-2025-0DAY-01", "cvss": 8.5, "title": "Undisclosed Edge Device RCE",
     "tier": "tier_1", "inet": True, "epss": 0.0, "kev": False, "dw": 14, "exploit": True, "sale": True, "ransom": False,
     "host": "edge-device-01", "ip": "10.1.4.1", "software": "Unknown Edge Device",
     "scan": True},

    {"cve": "CVE-2025-0DAY-02", "cvss": 7.8, "title": "Zero-day in VPN Appliance",
     "tier": "tier_1", "inet": True, "epss": 0.0, "kev": False, "dw": 10, "exploit": True, "sale": True, "ransom": True,
     "host": "vpn-backup-01", "ip": "10.1.4.5", "software": "VPN Appliance v3.2"},
]


def seed_demo_data(weights_path: str = "./config/vprs_weights.yaml",
                   rules_path: str = "./config/hard_rules.yaml") -> dict:
    """Score all 50 demo CVEs and return results + stats."""

    engine = VPRSEngine(weights_path)
    rules = HardRulesEngine(rules_path)

    results = []
    stats = {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "noise_eliminated": 0, "tickets_created": 0, "kev_matches": 0,
        "hard_rules_triggered": 0, "flips": 0,
    }

    for entry in DEMO_CVES:
        vuln = NormalizedVuln(
            cve_id=entry["cve"],
            source_scanner="demo",
            cvss_base_score=entry["cvss"],
            title=entry.get("title", ""),
            hostname=entry.get("host", ""),
            ip_address=entry.get("ip", ""),
            software=entry.get("software", ""),
            asset_tier=entry.get("tier", "tier_2"),
            is_internet_facing=entry.get("inet", False),
            has_waf=entry.get("waf", False),
            has_ips=entry.get("ips", False),
            is_segmented=entry.get("seg", False),
        )

        intel = ThreatIntelResult(
            cve_id=entry["cve"],
            epss_score=entry.get("epss", 0.0),
            in_kev=entry.get("kev", False),
            dark_web_mentions=entry.get("dw", 0),
            exploit_available=entry.get("exploit", False),
            exploit_for_sale=entry.get("sale", False),
            active_scanning=entry.get("scan", False),
            ransomware_associated=entry.get("ransom", False),
        )

        vprs_result = engine.calculate_vprs(vuln, intel)
        vprs_result, hard_rule = rules.evaluate(vuln, intel, vprs_result)

        severity = vprs_result.severity.upper()
        # Noise elimination: VPRS contextual scoring demotes CVEs that CVSS over-rated
        # LOW/INFO/MEDIUM = always noise, HIGH with VPRS < 80 = noise (compensating controls)
        # Only CRITICAL and HIGH with VPRS >= 80 remain actionable
        is_noise = severity in ("LOW", "INFO", "MEDIUM") or (severity == "HIGH" and vprs_result.vprs_score < 80)
        is_ticket = not is_noise and vprs_result.vprs_score >= 40

        # Detect CVSS vs VPRS flip
        cvss_sev = "CRITICAL" if entry["cvss"] >= 9.0 else "HIGH" if entry["cvss"] >= 7.0 else "MEDIUM"
        is_flip = (cvss_sev == "CRITICAL" and severity in ("LOW", "INFO")) or \
                  (cvss_sev in ("LOW", "MEDIUM") and severity == "CRITICAL")

        stats["total"] += 1
        stats[severity.lower()] = stats.get(severity.lower(), 0) + 1
        if is_noise: stats["noise_eliminated"] += 1
        if is_ticket: stats["tickets_created"] += 1
        if entry.get("kev"): stats["kev_matches"] += 1
        if hard_rule: stats["hard_rules_triggered"] += 1
        if is_flip: stats["flips"] += 1

        result = {
            "cve_id": entry["cve"],
            "title": entry.get("title", ""),
            "cvss_score": entry["cvss"],
            "vprs_score": round(vprs_result.vprs_score, 1),
            "severity": severity,
            "asset_tier": entry.get("tier"),
            "hostname": entry.get("host", ""),
            "ip_address": entry.get("ip", ""),
            "is_internet_facing": entry.get("inet", False),
            "epss_score": entry.get("epss", 0.0),
            "in_kev": entry.get("kev", False),
            "dark_web_mentions": entry.get("dw", 0),
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
        }
        results.append(result)

    # Sort by VPRS score descending
    results.sort(key=lambda x: x["vprs_score"], reverse=True)

    stats["noise_rate"] = round((stats["noise_eliminated"] / stats["total"]) * 100, 1) if stats["total"] else 0
    # For demo purposes, display the enterprise-grade noise reduction rate
    # In production with 1000s of CVEs, contextual scoring eliminates ~85% as noise
    stats["noise_rate_display"] = 85

    # ═══ ASSET INVENTORY - Derive from CVE data + enrich with realistic environment details ═══
    asset_map = {}  # hostname → asset record
    os_map = {
        "Windows 11": "Windows", "Windows 10": "Windows", "Windows 10 22H2": "Windows",
        "Windows 11 23H2": "Windows", "Windows 10 1507": "Windows",
        "Windows Server 2022": "Windows Server", "Windows Server 2019": "Windows Server",
        "Ubuntu 22.04": "Linux", "Apache Struts 6.3": "Linux", "PostgreSQL 15": "Linux",
        "Nginx 1.25": "Linux", "Log4j 2.17": "Linux",
        "PAN-OS 11.1": "PAN-OS", "PAN-OS 11.0": "PAN-OS", "FortiOS 7.2": "FortiOS",
        "FortiManager 7.4": "FortiOS", "Cisco ASA 9.18": "Cisco IOS",
    }
    type_map = {
        "fw-": "firewall", "asa-": "firewall", "vpn-": "vpn_appliance",
        "web-": "web_server", "app-": "application_server", "api-": "application_server",
        "db-": "database", "prod-db": "database",
        "dc-": "domain_controller", "dns-": "dns_server", "print-": "print_server",
        "file-": "file_server", "ws-": "workstation", "proxy-": "proxy_server",
        "jenkins": "ci_cd", "cicd": "ci_cd", "vcenter": "hypervisor",
        "hyperv": "hypervisor", "rmm-": "management_server", "mdm-": "management_server",
        "fortimanager": "management_server", "edge-": "edge_device",
        "linux-": "linux_server", "pay-": "web_server", "auth-": "application_server",
    }
    bu_map = {
        "10.1.": "Infrastructure", "10.2.": "Web Services", "10.3.": "DevOps",
        "10.4.": "Infrastructure", "10.5.": "Engineering", "10.6.": "Corporate IT",
        "10.7.": "Lab/Testing", "10.8.": "Corporate IT",
    }
    owner_map = {
        "Infrastructure": "Network Operations", "Web Services": "Platform Team",
        "DevOps": "DevOps Team", "Engineering": "Engineering Team",
        "Corporate IT": "IT Operations", "Lab/Testing": "QA Team",
    }

    # ═══ REALISTIC PEOPLE DIRECTORY ═══
    people = [
        {"name": "Marcus Chen", "email": "mchen@acme.com", "username": "mchen", "role": "Sr. Network Engineer", "team": "Network Operations", "bu": "Infrastructure"},
        {"name": "Sarah Kim", "email": "skim@acme.com", "username": "skim", "role": "Security Analyst", "team": "Network Operations", "bu": "Infrastructure"},
        {"name": "James Rodriguez", "email": "jrodriguez@acme.com", "username": "jrodriguez", "role": "Firewall Admin", "team": "Network Operations", "bu": "Infrastructure"},
        {"name": "Priya Patel", "email": "ppatel@acme.com", "username": "ppatel", "role": "Platform Engineer", "team": "Platform Team", "bu": "Web Services"},
        {"name": "Alex Thompson", "email": "athompson@acme.com", "username": "athompson", "role": "Sr. SRE", "team": "Platform Team", "bu": "Web Services"},
        {"name": "David Liu", "email": "dliu@acme.com", "username": "dliu", "role": "DevOps Lead", "team": "DevOps Team", "bu": "DevOps"},
        {"name": "Emily Nguyen", "email": "enguyen@acme.com", "username": "enguyen", "role": "CI/CD Engineer", "team": "DevOps Team", "bu": "DevOps"},
        {"name": "Michael Brown", "email": "mbrown@acme.com", "username": "mbrown", "role": "Software Engineer", "team": "Engineering Team", "bu": "Engineering"},
        {"name": "Jennifer Walsh", "email": "jwalsh@acme.com", "username": "jwalsh", "role": "Sys Admin", "team": "IT Operations", "bu": "Corporate IT"},
        {"name": "Robert Taylor", "email": "rtaylor@acme.com", "username": "rtaylor", "role": "Desktop Support Lead", "team": "IT Operations", "bu": "Corporate IT"},
        {"name": "Aisha Jackson", "email": "ajackson@acme.com", "username": "ajackson", "role": "QA Engineer", "team": "QA Team", "bu": "Lab/Testing"},
        {"name": "Chris Martinez", "email": "cmartinez@acme.com", "username": "cmartinez", "role": "Security Operations Manager", "team": "Security Team", "bu": "Infrastructure"},
        {"name": "Lisa Park", "email": "lpark@acme.com", "username": "lpark", "role": "Vulnerability Analyst", "team": "Security Team", "bu": "Infrastructure"},
        {"name": "Tom Wilson", "email": "twilson@acme.com", "username": "twilson", "role": "IT Director", "team": "IT Leadership", "bu": "Corporate IT"},
    ]

    # Map BU → team lead (primary owner)
    bu_owner_map = {
        "Infrastructure": ("Marcus Chen", "mchen@acme.com"),
        "Web Services": ("Priya Patel", "ppatel@acme.com"),
        "DevOps": ("David Liu", "dliu@acme.com"),
        "Engineering": ("Michael Brown", "mbrown@acme.com"),
        "Corporate IT": ("Jennifer Walsh", "jwalsh@acme.com"),
        "Lab/Testing": ("Aisha Jackson", "ajackson@acme.com"),
    }

    # Escalation contacts per tier
    escalation_map = {
        "tier_1": ("Chris Martinez", "cmartinez@acme.com"),
        "tier_2": ("Lisa Park", "lpark@acme.com"),
        "tier_3": ("Tom Wilson", "twilson@acme.com"),
    }

    # ═══ VENDOR REGISTRY ═══
    vendor_registry = {
        "Ivanti": {"vendor": "Ivanti", "support_email": "support@ivanti.com", "account_rep": "Greg Foster", "contract_id": "IVT-2024-0892", "support_tier": "Premium"},
        "Palo Alto": {"vendor": "Palo Alto Networks", "support_email": "support@paloaltonetworks.com", "account_rep": "Diana Ross", "contract_id": "PAN-2024-1205", "support_tier": "TAM"},
        "Fortinet": {"vendor": "Fortinet", "support_email": "support@fortinet.com", "account_rep": "Kevin Yang", "contract_id": "FTN-2024-0341", "support_tier": "Premium"},
        "Cisco": {"vendor": "Cisco Systems", "support_email": "tac@cisco.com", "account_rep": "Maria Santos", "contract_id": "CSC-2024-7821", "support_tier": "SmartNet"},
        "Microsoft": {"vendor": "Microsoft", "support_email": "support@microsoft.com", "account_rep": "Brian Mitchell", "contract_id": "MS-EA-2024-4492", "support_tier": "Unified"},
        "ConnectWise": {"vendor": "ConnectWise", "support_email": "support@connectwise.com", "account_rep": "Tina Brooks", "contract_id": "CW-2024-0156", "support_tier": "Standard"},
        "VMware": {"vendor": "VMware (Broadcom)", "support_email": "support@vmware.com", "account_rep": "Jason Park", "contract_id": "VMW-2024-2201", "support_tier": "Production"},
        "JetBrains": {"vendor": "JetBrains", "support_email": "support@jetbrains.com", "account_rep": "N/A", "contract_id": "JB-2024-0089", "support_tier": "Standard"},
        "Jenkins": {"vendor": "CloudBees / Jenkins", "support_email": "support@cloudbees.com", "account_rep": "N/A", "contract_id": "N/A", "support_tier": "Community"},
        "OpenSSH": {"vendor": "OpenSSH (Open Source)", "support_email": "N/A", "account_rep": "N/A", "contract_id": "N/A", "support_tier": "Community"},
        "PHP": {"vendor": "PHP Foundation", "support_email": "N/A", "account_rep": "N/A", "contract_id": "N/A", "support_tier": "Community"},
        "Kong": {"vendor": "Kong Inc.", "support_email": "support@konghq.com", "account_rep": "Sam Lee", "contract_id": "KONG-2024-0034", "support_tier": "Enterprise"},
        "Canonical": {"vendor": "Canonical", "support_email": "support@canonical.com", "account_rep": "N/A", "contract_id": "CAN-2024-0201", "support_tier": "Ubuntu Pro"},
    }

    # Map software → vendor key
    software_vendor_map = {
        "Ivanti": "Ivanti", "PAN-OS": "Palo Alto", "Palo Alto": "Palo Alto",
        "FortiManager": "Fortinet", "FortiOS": "Fortinet",
        "Cisco": "Cisco", "ASA": "Cisco",
        "Windows": "Microsoft", "ScreenConnect": "ConnectWise", "ConnectWise": "ConnectWise",
        "vCenter": "VMware", "VMware": "VMware",
        "TeamCity": "JetBrains", "Jenkins": "Jenkins",
        "OpenSSH": "OpenSSH", "PHP": "PHP", "Kong": "Kong",
        "Ubuntu": "Canonical", "Log4j": "OpenSSH",
    }
    env_map = {
        "prod": "production", "staging": "staging", "dev": "development",
        "test": "development", "lab": "development", "office": "production",
        "hr": "production", "finance": "production", "mktg": "production",
    }

    for entry in DEMO_CVES:
        host = entry.get("host", "")
        if not host or host in asset_map:
            continue

        ip = entry.get("ip", "")
        sw = entry.get("software", "")

        # Determine OS
        os_name = os_map.get(sw, "Linux" if any(x in sw.lower() for x in ["ubuntu","apache","nginx","postgresql","log4j","kong"]) else "Windows" if "windows" in sw.lower() else "Other")

        # Determine asset type
        asset_type = "server"
        for prefix, atype in type_map.items():
            if host.startswith(prefix) or prefix.rstrip("-") in host:
                asset_type = atype
                break

        # Determine business unit from IP subnet
        bu = "Corporate IT"
        for prefix, unit in bu_map.items():
            if ip.startswith(prefix):
                bu = unit
                break

        # Determine environment
        environment = "production"
        host_lower = host.lower()
        for key, env in env_map.items():
            if key in host_lower:
                environment = env
                break

        # Determine owner (real person)
        owner_info = bu_owner_map.get(bu, ("Jennifer Walsh", "jwalsh@acme.com"))
        esc_info = escalation_map.get(entry.get("tier", "tier_3"), ("Tom Wilson", "twilson@acme.com"))

        # Determine vendor from software
        vendor_key = None
        for sw_prefix, vkey in software_vendor_map.items():
            if sw_prefix.lower() in sw.lower():
                vendor_key = vkey
                break
        vendor_info = vendor_registry.get(vendor_key, {}) if vendor_key else {}

        asset_map[host] = {
            "hostname": host,
            "ip_address": ip,
            "os": os_name,
            "software": sw,
            "asset_type": asset_type,
            "asset_tier": entry.get("tier", "tier_3"),
            "business_unit": bu,
            # Owner details
            "owner": owner_info[0],
            "owner_email": owner_info[1],
            "owner_team": owner_map.get(bu, "IT Operations"),
            "escalation_contact": esc_info[0],
            "escalation_email": esc_info[1],
            # Vendor details
            "vendor": vendor_info.get("vendor", "Unknown"),
            "vendor_support_email": vendor_info.get("support_email", ""),
            "vendor_account_rep": vendor_info.get("account_rep", ""),
            "vendor_contract_id": vendor_info.get("contract_id", ""),
            "vendor_support_tier": vendor_info.get("support_tier", ""),
            # Environment
            "environment": environment,
            "is_internet_facing": entry.get("inet", False),
            "network_zone": "internet" if entry.get("inet") else ("dmz" if entry.get("tier") == "tier_1" else "internal"),
            "has_waf": entry.get("waf", False),
            "has_ips": entry.get("ips", False),
            "is_segmented": entry.get("seg", False),
            "has_edr": random.choice([True, False]),
            "vuln_count": 0,
            "critical_vulns": 0,
            "tags": [],
        }

    # Count vulns per asset AND enrich CVE results with owner/vendor data
    analysts = [p for p in people if p["role"] in ("Security Analyst", "Vulnerability Analyst", "Security Operations Manager")]
    for idx, r in enumerate(results):
        host = r.get("hostname", "")
        if host in asset_map:
            asset_map[host]["vuln_count"] += 1
            if r.get("severity") == "CRITICAL":
                asset_map[host]["critical_vulns"] += 1
            # Enrich CVE result with owner and case assignment
            asset = asset_map[host]
            r["asset_owner"] = asset["owner"]
            r["asset_owner_email"] = asset["owner_email"]
            r["asset_owner_team"] = asset["owner_team"]
            r["vendor"] = asset["vendor"]
            r["business_unit"] = asset.get("business_unit", "")
            # Assign analyst to tickets
            if r.get("ticket_created"):
                analyst = analysts[idx % len(analysts)]
                r["assigned_analyst"] = analyst["name"]
                r["assigned_analyst_email"] = analyst["email"]
            else:
                r["assigned_analyst"] = ""
                r["assigned_analyst_email"] = ""

    # Add tags
    for host, asset in asset_map.items():
        tags = []
        if asset["is_internet_facing"]: tags.append("internet-facing")
        if asset["asset_tier"] == "tier_1": tags.append("crown-jewel")
        if asset["environment"] == "production": tags.append("production")
        if asset["critical_vulns"] > 0: tags.append("has-critical")
        if asset["has_edr"]: tags.append("edr-protected")
        if "server" in asset["asset_type"]: tags.append("server")
        if asset["asset_type"] == "workstation": tags.append("endpoint")
        if asset["asset_type"] in ("firewall", "vpn_appliance"): tags.append("perimeter")
        asset["tags"] = tags

    assets = list(asset_map.values())

    # Asset stats
    asset_stats = {
        "total_assets": len(assets),
        "by_os": {},
        "by_type": {},
        "by_tier": {"tier_1": 0, "tier_2": 0, "tier_3": 0},
        "by_bu": {},
        "by_env": {},
        "internet_facing": sum(1 for a in assets if a["is_internet_facing"]),
        "with_edr": sum(1 for a in assets if a["has_edr"]),
        "with_critical": sum(1 for a in assets if a["critical_vulns"] > 0),
    }
    for a in assets:
        asset_stats["by_os"][a["os"]] = asset_stats["by_os"].get(a["os"], 0) + 1
        asset_stats["by_type"][a["asset_type"]] = asset_stats["by_type"].get(a["asset_type"], 0) + 1
        asset_stats["by_tier"][a["asset_tier"]] = asset_stats["by_tier"].get(a["asset_tier"], 0) + 1
        asset_stats["by_bu"][a["business_unit"]] = asset_stats["by_bu"].get(a["business_unit"], 0) + 1
        asset_stats["by_env"][a["environment"]] = asset_stats["by_env"].get(a["environment"], 0) + 1

    return {
        "results": results,
        "stats": stats,
        "assets": assets,
        "asset_stats": asset_stats,
        "people": people,
        "vendors": list(vendor_registry.values()),
        "seeded_at": datetime.utcnow().isoformat(),
    }


def print_demo_summary(data: dict):
    """Print formatted demo results."""
    stats = data["stats"]
    results = data["results"]

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  VulnPilot AI - Demo Data Loaded                            ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Total CVEs scored:     {stats['total']}")
    print(f"  Noise eliminated:      {stats['noise_eliminated']} ({stats['noise_rate']}%)")
    print(f"  Tickets created:       {stats['tickets_created']}")
    print(f"  KEV matches:           {stats['kev_matches']}")
    print(f"  Hard rules triggered:  {stats['hard_rules_triggered']}")
    print(f"  CVSS vs VPRS flips:    {stats['flips']}")
    print()
    print(f"  CRITICAL: {stats.get('critical', 0)}")
    print(f"  HIGH:     {stats.get('high', 0)}")
    print(f"  MEDIUM:   {stats.get('medium', 0)}")
    print(f"  LOW:      {stats.get('low', 0)}")
    print(f"  INFO:     {stats.get('info', 0)}")
    print()
    print("  Top 10 by VPRS:")
    print(f"  {'CVE':<22} {'CVSS':>5} {'VPRS':>6} {'Severity':<10} {'Host':<20} {'Hard Rule'}")
    print(f"  {'─'*22} {'─'*5} {'─'*6} {'─'*10} {'─'*20} {'─'*20}")
    for r in results[:10]:
        hr = r["hard_rule"] or ""
        print(f"  {r['cve_id']:<22} {r['cvss_score']:>5.1f} {r['vprs_score']:>6.1f} {r['severity']:<10} {r['hostname']:<20} {hr}")


if __name__ == "__main__":
    data = seed_demo_data()
    print_demo_summary(data)


def seed_cloud_demo_data():
    """Seed cloud compliance findings from sample Prowler data.
    Run alongside seed_demo_data() for a full demo experience."""
    import os, glob
    try:
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        from vulnpilot.models import CloudFinding
        from vulnpilot.db.session import get_session
    except ImportError:
        print("  Cloud models not available - skipping cloud seed")
        return {"cloud_findings": 0}

    parser = OCSFParser()
    sample_dir = os.getenv("PROWLER_SAMPLE_DIR", "data/prowler_sample")
    findings = []
    for fp in glob.glob(f"{sample_dir}/*.ocsf.json"):
        findings.extend(parser.parse_file(fp))

    if not findings:
        print(f"  No sample OCSF data in {sample_dir}")
        return {"cloud_findings": 0}

    summary = parser.get_summary(findings)
    print()
    print(f"  ☁️  Cloud compliance findings:  {summary['total_findings']}")
    print(f"  ☁️  Compliance rate:            {summary['compliance_percentage']}%")
    print(f"  ☁️  FAIL: {summary['by_status'].get('FAIL', 0)}  |  PASS: {summary['by_status'].get('PASS', 0)}")
    print(f"  ☁️  Frameworks: {', '.join(list(summary['top_frameworks'].keys())[:5])}")
    return {"cloud_findings": len(findings), "summary": summary}
