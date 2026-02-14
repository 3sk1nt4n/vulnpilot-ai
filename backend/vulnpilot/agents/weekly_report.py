"""
VulnPilot AI - Weekly Trend Reports
Generates weekly/monthly summaries of vulnerability management activity.
Tracks: noise reduction, SLA compliance, top risks, remediation velocity.
Output: JSON (for API), Markdown (for email/Slack), or dict (for dashboard).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TrendMetrics:
    """Metrics for a single reporting period."""
    period_start: str
    period_end: str

    # --- Volume ---
    total_vulns_ingested: int = 0
    total_vulns_scored: int = 0
    noise_eliminated: int = 0
    noise_elimination_rate: float = 0.0
    tickets_created: int = 0

    # --- Severity Distribution ---
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # --- SLA Compliance ---
    tickets_resolved_on_time: int = 0
    tickets_breached_sla: int = 0
    sla_compliance_rate: float = 0.0
    avg_resolution_hours: float = 0.0

    # --- Hard Rules (Lock 1) ---
    hard_rules_triggered: int = 0
    kev_matches_found: int = 0
    ransomware_vulns_found: int = 0

    # --- Adversarial AI (Lock 2) ---
    debates_run: int = 0
    adversarial_overrides: int = 0
    override_rate: float = 0.0

    # --- Drift Detector (Lock 3) ---
    drift_events: int = 0
    auto_promotions: int = 0

    # --- Top Risks ---
    top_cves: list[dict] = field(default_factory=list)  # Top 10 by VPRS
    top_assets: list[dict] = field(default_factory=list)  # Most vulnerable assets

    # --- Cloud Compliance (Prowler + Custodian) ---
    cloud_findings_total: int = 0
    cloud_findings_pass: int = 0
    cloud_findings_fail: int = 0
    cloud_compliance_pct: float = 0.0
    cloud_critical_findings: int = 0
    cloud_high_findings: int = 0
    cloud_frameworks_covered: list[str] = field(default_factory=list)
    cloud_top_failures: list[dict] = field(default_factory=list)


@dataclass
class TrendComparison:
    """Week-over-week or month-over-month comparison."""
    current: TrendMetrics
    previous: TrendMetrics

    @property
    def vuln_volume_change(self) -> float:
        if self.previous.total_vulns_ingested == 0:
            return 0.0
        return round(
            ((self.current.total_vulns_ingested - self.previous.total_vulns_ingested)
             / self.previous.total_vulns_ingested) * 100, 1
        )

    @property
    def noise_rate_change(self) -> float:
        return round(self.current.noise_elimination_rate - self.previous.noise_elimination_rate, 1)

    @property
    def sla_compliance_change(self) -> float:
        return round(self.current.sla_compliance_rate - self.previous.sla_compliance_rate, 1)

    @property
    def critical_change(self) -> int:
        return self.current.critical_count - self.previous.critical_count


class WeeklyReportGenerator:
    """Generates weekly trend reports from scoring data."""

    def generate_from_results(
        self,
        results: list[dict],
        period_start: datetime,
        period_end: datetime,
    ) -> TrendMetrics:
        """Generate metrics from a list of pipeline results.

        Args:
            results: List of pipeline result dicts (from batch processing)
            period_start: Report period start
            period_end: Report period end

        Returns:
            TrendMetrics for the period
        """
        metrics = TrendMetrics(
            period_start=period_start.isoformat()[:10],
            period_end=period_end.isoformat()[:10],
        )

        metrics.total_vulns_ingested = len(results)

        for r in results:
            vprs_score = r.get("vprs_score", 0)
            severity = r.get("severity", "info")

            metrics.total_vulns_scored += 1

            # Severity counts
            if severity == "critical":
                metrics.critical_count += 1
            elif severity == "high":
                metrics.high_count += 1
            elif severity == "medium":
                metrics.medium_count += 1
            elif severity == "low":
                metrics.low_count += 1
            else:
                metrics.info_count += 1
                metrics.noise_eliminated += 1

            # Count noise (below ticket threshold)
            if vprs_score < 40:
                metrics.noise_eliminated += 1

            if r.get("ticket_created"):
                metrics.tickets_created += 1
            if r.get("hard_rule_triggered"):
                metrics.hard_rules_triggered += 1
            if r.get("in_kev"):
                metrics.kev_matches_found += 1
            if r.get("debate_applied"):
                metrics.adversarial_overrides += 1
                metrics.debates_run += 1

        # Calculate rates
        if metrics.total_vulns_ingested > 0:
            metrics.noise_elimination_rate = round(
                (metrics.noise_eliminated / metrics.total_vulns_ingested) * 100, 1
            )

        if metrics.debates_run > 0:
            metrics.override_rate = round(
                (metrics.adversarial_overrides / metrics.debates_run) * 100, 1
            )

        # Top CVEs by score
        scored = sorted(results, key=lambda x: x.get("vprs_score", 0), reverse=True)
        metrics.top_cves = [
            {"cve_id": r.get("cve_id"), "vprs_score": r.get("vprs_score"), "severity": r.get("severity")}
            for r in scored[:10]
        ]

        # Cloud compliance data (from Prowler/Custodian)
        try:
            self._populate_cloud_metrics(metrics)
        except Exception as e:
            logger.debug(f"Cloud metrics not available: {e}")

        return metrics

    def _populate_cloud_metrics(self, metrics: TrendMetrics) -> None:
        """Pull cloud compliance summary from OCSF parser."""
        import os, glob
        from vulnpilot.cloud.ocsf_parser import OCSFParser
        parser = OCSFParser()
        sample_dir = os.getenv("PROWLER_SAMPLE_DIR", "data/prowler_sample")
        prowler_dir = os.getenv("PROWLER_OUTPUT_DIR", "/data/prowler")
        all_findings = []
        for d in [sample_dir, prowler_dir]:
            for fp in glob.glob(f"{d}/*.ocsf.json"):
                all_findings.extend(parser.parse_file(fp))
        if not all_findings:
            return
        summary = parser.get_summary(all_findings)
        metrics.cloud_findings_total = summary.get("total_findings", 0)
        metrics.cloud_findings_pass = summary.get("pass_count", 0)
        metrics.cloud_findings_fail = summary.get("fail_count", 0)
        metrics.cloud_compliance_pct = summary.get("compliance_percentage", 0)
        sev = summary.get("by_severity", {})
        metrics.cloud_critical_findings = sev.get("critical", 0)
        metrics.cloud_high_findings = sev.get("high", 0)
        metrics.cloud_frameworks_covered = list(summary.get("top_frameworks", {}).keys())[:8]
        # Top failures
        failures = [f for f in all_findings if f.status == "FAIL"]
        failures.sort(key=lambda f: f.severity_score, reverse=True)
        metrics.cloud_top_failures = [
            {"check_id": f.check_id, "title": f.title[:100], "severity": f.severity, "resource": f.resource_name}
            for f in failures[:5]
        ]

    def to_markdown(self, metrics: TrendMetrics) -> str:
        """Generate a Markdown report for email/Slack."""
        return f"""# VulnPilot AI - Weekly Report
**Period:** {metrics.period_start} to {metrics.period_end}

## Summary
| Metric | Value |
|--------|-------|
| Vulnerabilities Ingested | {metrics.total_vulns_ingested:,} |
| Noise Eliminated | {metrics.noise_eliminated:,} ({metrics.noise_elimination_rate}%) |
| Tickets Created | {metrics.tickets_created} |
| KEV Matches | {metrics.kev_matches_found} |
| Hard Rules Triggered | {metrics.hard_rules_triggered} |
| Adversarial Overrides | {metrics.adversarial_overrides} |

## Severity Distribution
| Severity | Count |
|----------|-------|
| CRITICAL | {metrics.critical_count} |
| HIGH | {metrics.high_count} |
| MEDIUM | {metrics.medium_count} |
| LOW | {metrics.low_count} |
| INFO (noise) | {metrics.info_count} |

## Top 10 Risks
| # | CVE | VPRS | Severity |
|---|-----|------|----------|
""" + "\n".join(
            f"| {i+1} | {c['cve_id']} | {c['vprs_score']:.1f} | {c['severity'].upper()} |"
            for i, c in enumerate(metrics.top_cves)
        ) + f"""

## Triple-Lock Safety
- **Lock 1 (Hard Rules):** {metrics.hard_rules_triggered} triggered
- **Lock 2 (Adversarial AI):** {metrics.debates_run} debates, {metrics.adversarial_overrides} overrides ({metrics.override_rate}%)
- **Lock 3 (Drift Detector):** {metrics.drift_events} drift events, {metrics.auto_promotions} auto-promotions

## Cloud Compliance (Prowler)
| Metric | Value |
|--------|-------|
| Total Checks | {metrics.cloud_findings_total} |
| Passed | {metrics.cloud_findings_pass} |
| Failed | {metrics.cloud_findings_fail} |
| Compliance Rate | {metrics.cloud_compliance_pct}% |
| Critical Findings | {metrics.cloud_critical_findings} |
| High Findings | {metrics.cloud_high_findings} |
| Frameworks | {', '.join(metrics.cloud_frameworks_covered) if metrics.cloud_frameworks_covered else 'N/A'} |

""" + ("""### Top Cloud Failures
| # | Check | Severity | Resource |
|---|-------|----------|----------|
""" + "\n".join(
            f"| {i+1} | {f['title'][:60]} | {f['severity'].upper()} | {f['resource']} |"
            for i, f in enumerate(metrics.cloud_top_failures)
        ) if metrics.cloud_top_failures else "") + f"""

## Compliance Framework Mapping
| Framework | Requirement | VulnPilot Coverage |
|-----------|-----------|-------------------|
| PCI DSS 4.0 | 6.3.3 - Patch critical vulns within 30 days | SLA tracking: {metrics.tickets_resolved_on_time} on-time, {metrics.tickets_breached_sla} breached |
| PCI DSS 4.0 | 11.3.1 - Quarterly vulnerability scans | {metrics.total_vulns_ingested:,} vulns ingested this period |
| NIST CSF | ID.RA-1 - Asset vulnerabilities identified | {metrics.total_vulns_ingested:,} vulns scored with VPRS |
| NIST CSF | RS.MI-3 - Newly identified vulns mitigated | {metrics.tickets_created} tickets auto-created with SLA |
| NIST 800-53 | RA-5 - Vulnerability Monitoring and Scanning | Continuous via scanner integrations + Drift Detector |
| NIST 800-53 | SI-2 - Flaw Remediation | {metrics.tickets_created} remediation tickets with owner assignment |
| SOC 2 | CC7.1 - Detect and monitor anomalies | {metrics.kev_matches_found} KEV matches, {metrics.drift_events} drift events |
| ISO 27001 | A.12.6.1 - Technical vulnerability management | VPRS scoring with {metrics.noise_elimination_rate}% noise reduction |
| HIPAA | §164.312(a)(1) - Technical safeguards | Asset-tier scoring prioritizes systems with PHI/ePHI |
| CISA BOD 22-01 | KEV remediation within 14 days | {metrics.kev_matches_found} KEV vulns auto-flagged CRITICAL |

---
*Generated by VulnPilot AI | Solvent CyberSecurity*
"""

    def to_json(self, metrics: TrendMetrics) -> dict:
        """Generate JSON report for API responses."""
        return {
            "report_type": "weekly",
            "period": {
                "start": metrics.period_start,
                "end": metrics.period_end,
            },
            "summary": {
                "total_ingested": metrics.total_vulns_ingested,
                "noise_eliminated": metrics.noise_eliminated,
                "noise_rate": metrics.noise_elimination_rate,
                "tickets_created": metrics.tickets_created,
            },
            "severity": {
                "critical": metrics.critical_count,
                "high": metrics.high_count,
                "medium": metrics.medium_count,
                "low": metrics.low_count,
                "info": metrics.info_count,
            },
            "safety": {
                "hard_rules_triggered": metrics.hard_rules_triggered,
                "kev_matches": metrics.kev_matches_found,
                "adversarial_overrides": metrics.adversarial_overrides,
                "drift_events": metrics.drift_events,
            },
            "top_risks": metrics.top_cves,
            "cloud_compliance": {
                "total_checks": metrics.cloud_findings_total,
                "passed": metrics.cloud_findings_pass,
                "failed": metrics.cloud_findings_fail,
                "compliance_percentage": metrics.cloud_compliance_pct,
                "critical_findings": metrics.cloud_critical_findings,
                "high_findings": metrics.cloud_high_findings,
                "frameworks_covered": metrics.cloud_frameworks_covered,
                "top_failures": metrics.cloud_top_failures,
            },
            "compliance": {
                "pci_dss_4": {
                    "6.3.3_patching": f"{metrics.tickets_resolved_on_time} on-time, {metrics.tickets_breached_sla} breached",
                    "11.3.1_scanning": f"{metrics.total_vulns_ingested} vulns ingested",
                },
                "nist_csf": {
                    "ID.RA-1_identification": f"{metrics.total_vulns_ingested} vulns scored",
                    "RS.MI-3_mitigation": f"{metrics.tickets_created} tickets created",
                },
                "nist_800_53": {
                    "RA-5_monitoring": "Continuous via scanner integrations + Drift Detector",
                    "SI-2_remediation": f"{metrics.tickets_created} remediation tickets",
                },
                "soc2": {
                    "CC7.1_detection": f"{metrics.kev_matches_found} KEV, {metrics.drift_events} drift events",
                },
                "iso_27001": {
                    "A.12.6.1_vuln_mgmt": f"{metrics.noise_elimination_rate}% noise reduction",
                },
                "hipaa": {
                    "164.312_technical_safeguards": "Asset-tier scoring prioritizes PHI/ePHI systems",
                },
                "cisa_bod_22_01": {
                    "kev_remediation": f"{metrics.kev_matches_found} KEV vulns auto-flagged CRITICAL",
                },
            },
            "generated_at": datetime.utcnow().isoformat(),
        }
