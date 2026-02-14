"""
VulnPilot AI - Jira Ticket Provider
Creates and tracks remediation tickets in Jira Cloud/Server.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import httpx

from vulnpilot.tickets.base import TicketProvider, TicketResult, SLACheckResult, SLAStatusEnum

logger = logging.getLogger(__name__)


class JiraProvider(TicketProvider):
    """Jira Cloud/Server ticket integration."""

    def __init__(self):
        self.url = os.getenv("JIRA_URL", "")
        self.username = os.getenv("JIRA_USERNAME", "")
        self.api_token = os.getenv("JIRA_API_TOKEN", "")
        self.project_key = os.getenv("JIRA_PROJECT_KEY", "VULN")
        self.timeout = 30.0

    def _auth(self) -> tuple:
        return (self.username, self.api_token)

    async def create_ticket(
        self, cve_id: str, title: str, description: str,
        priority: str, assigned_to: str, sla_hours: int,
        vprs_score: float, justification: str, remediation_steps: list[str],
    ) -> TicketResult:
        try:
            priority_map = {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}
            steps_text = "\n".join(f"# {s}" for s in remediation_steps)

            # Jira description uses wiki markup (or ADF for Cloud)
            jira_desc = (
                f"h2. VulnPilot AI - Automated Remediation Ticket\n\n"
                f"||Field||Value||\n"
                f"|CVE|{cve_id}|\n"
                f"|VPRS Score|{vprs_score}/100|\n"
                f"|Priority|{priority}|\n"
                f"|SLA|{sla_hours} hours|\n\n"
                f"h3. Justification\n{justification}\n\n"
                f"h3. Remediation Steps\n{steps_text}\n\n"
                f"h3. Full Details\n{description}"
            )

            payload = {
                "fields": {
                    "project": {"key": self.project_key},
                    "summary": title,
                    "description": jira_desc,
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": priority_map.get(priority, "Medium")},
                    "labels": ["vulnpilot", "security", cve_id.lower().replace("-", "_")],
                }
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.url}/rest/api/2/issue",
                    auth=self._auth(), json=payload,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                result = resp.json()

                issue_key = result.get("key", "")
                issue_id = result.get("id", "")

                logger.info(f"Jira ticket created: {issue_key} for {cve_id}")

                return TicketResult(
                    ticket_id=issue_id,
                    ticket_url=f"{self.url}/browse/{issue_key}",
                    provider="jira",
                    assigned_to=assigned_to,
                    sla_deadline=datetime.utcnow() + timedelta(hours=sla_hours),
                    sla_hours=sla_hours,
                )
        except Exception as e:
            logger.error(f"Jira ticket creation failed: {e}")
            return TicketResult(ticket_id="", provider="jira", success=False, error=str(e))

    async def check_sla(self, ticket_id: str) -> SLACheckResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.url}/rest/api/2/issue/{ticket_id}",
                    auth=self._auth(),
                )
                resp.raise_for_status()
                issue = resp.json()
                status = issue.get("fields", {}).get("status", {}).get("name", "Open")

                return SLACheckResult(
                    ticket_id=ticket_id,
                    status=SLAStatusEnum.ON_TRACK,
                    hours_remaining=0, percent_elapsed=0,
                    needs_nudge=False, needs_escalation=False,
                    current_ticket_status=status.lower(),
                )
        except Exception as e:
            logger.error(f"Jira SLA check failed: {e}")
            return SLACheckResult(
                ticket_id=ticket_id, status=SLAStatusEnum.ON_TRACK,
                hours_remaining=0, percent_elapsed=0,
                needs_nudge=False, needs_escalation=False, current_ticket_status="unknown")

    async def update_ticket(self, ticket_id: str, **kwargs) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.put(
                    f"{self.url}/rest/api/2/issue/{ticket_id}",
                    auth=self._auth(), json={"fields": kwargs},
                )
                return resp.status_code in (200, 204)
        except Exception:
            return False

    async def add_comment(self, ticket_id: str, comment: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.url}/rest/api/2/issue/{ticket_id}/comment",
                    auth=self._auth(), json={"body": comment},
                )
                return resp.status_code == 201
        except Exception:
            return False

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self.url}/rest/api/2/myself", auth=self._auth())
                return resp.status_code == 200
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "jira"
