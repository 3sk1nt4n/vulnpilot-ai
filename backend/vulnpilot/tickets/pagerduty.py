"""
VulnPilot AI - PagerDuty Incident Provider
Creates PagerDuty incidents for VPRS Critical (90+) findings.

Uses PagerDuty Events API v2 for triggering incidents.
Only fires for Critical severity to avoid alert fatigue.

Setup:
  PAGERDUTY_ROUTING_KEY=your-events-api-v2-routing-key
  PAGERDUTY_SEVERITY_THRESHOLD=90  (default: only VPRS 90+)
"""

import logging
import os
from datetime import datetime
from typing import Optional

import httpx

from vulnpilot.tickets.base import TicketProvider, TicketResult

logger = logging.getLogger(__name__)


class PagerDutyProvider(TicketProvider):
    """PagerDuty Events API v2 integration for critical vulnerability alerting."""

    EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self):
        self.routing_key = os.getenv("PAGERDUTY_ROUTING_KEY", "")
        self.severity_threshold = int(os.getenv("PAGERDUTY_SEVERITY_THRESHOLD", "90"))
        self.timeout = 15.0

    async def create_ticket(
        self,
        cve_id: str,
        title: str,
        description: str,
        severity: str = "critical",
        vprs_score: float = 0.0,
        assignee: str = "",
        **kwargs,
    ) -> TicketResult:
        """Create a PagerDuty incident via Events API v2.

        Only triggers if vprs_score >= threshold (default 90).
        """
        if vprs_score < self.severity_threshold:
            return TicketResult(
                success=False,
                ticket_id="",
                message=f"VPRS {vprs_score} below PagerDuty threshold ({self.severity_threshold}). No incident created.",
            )

        if not self.routing_key:
            return TicketResult(success=False, ticket_id="", message="PAGERDUTY_ROUTING_KEY not configured")

        # Map VPRS severity to PagerDuty severity
        pd_severity = "critical" if vprs_score >= 90 else "error" if vprs_score >= 70 else "warning"

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"vulnpilot-{cve_id}",  # Dedup: same CVE won't create duplicate incidents
            "payload": {
                "summary": f"[VulnPilot] {cve_id} - VPRS {vprs_score:.0f} - {title[:200]}",
                "severity": pd_severity,
                "source": "vulnpilot-ai",
                "component": cve_id,
                "group": "vulnerability-management",
                "class": "vprs_critical",
                "custom_details": {
                    "cve_id": cve_id,
                    "vprs_score": vprs_score,
                    "severity": severity,
                    "description": description[:1000],
                    "assignee": assignee,
                    "source": "VulnPilot AI Triple-Lock Pipeline",
                },
            },
            "links": [
                {"href": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "text": f"NVD: {cve_id}"},
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.EVENTS_URL, json=payload)

                if resp.status_code == 202:
                    data = resp.json()
                    dedup_key = data.get("dedup_key", f"vulnpilot-{cve_id}")
                    logger.info(f"PagerDuty incident triggered for {cve_id} (VPRS {vprs_score})")
                    return TicketResult(
                        success=True,
                        ticket_id=dedup_key,
                        url=f"https://events.pagerduty.com/v2/enqueue#{dedup_key}",
                        message=f"PagerDuty incident triggered: {cve_id}",
                    )
                else:
                    error = resp.text[:200]
                    logger.error(f"PagerDuty failed for {cve_id}: HTTP {resp.status_code} - {error}")
                    return TicketResult(success=False, ticket_id="", message=f"HTTP {resp.status_code}: {error}")

        except Exception as e:
            logger.error(f"PagerDuty error for {cve_id}: {e}")
            return TicketResult(success=False, ticket_id="", message=str(e))

    async def resolve_ticket(self, cve_id: str) -> bool:
        """Auto-resolve a PagerDuty incident when the CVE is remediated."""
        if not self.routing_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.EVENTS_URL, json={
                    "routing_key": self.routing_key,
                    "event_action": "resolve",
                    "dedup_key": f"vulnpilot-{cve_id}",
                })
                return resp.status_code == 202
        except Exception:
            return False

    async def health_check(self) -> bool:
        return bool(self.routing_key)

    @property
    def provider_name(self) -> str:
        return "pagerduty"
