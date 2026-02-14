"""
VulnPilot AI - ServiceNow Ticket Provider
Creates and tracks remediation tickets in ServiceNow ITSM.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import httpx

from vulnpilot.tickets.base import TicketProvider, TicketResult, SLACheckResult, SLAStatusEnum

logger = logging.getLogger(__name__)


class ServiceNowProvider(TicketProvider):
    """ServiceNow ITSM ticket integration."""

    def __init__(self):
        self.instance = os.getenv("SERVICENOW_INSTANCE", "")
        self.username = os.getenv("SERVICENOW_USERNAME", "")
        self.password = os.getenv("SERVICENOW_PASSWORD", "")
        self.table = "incident"  # or "sn_vul_vulnerability" for SecOps
        self.timeout = 30.0

    def _url(self, path: str) -> str:
        return f"{self.instance}/api/now/table/{path}"

    def _auth(self) -> tuple:
        return (self.username, self.password)

    async def create_ticket(
        self, cve_id: str, title: str, description: str,
        priority: str, assigned_to: str, sla_hours: int,
        vprs_score: float, justification: str, remediation_steps: list[str],
    ) -> TicketResult:
        try:
            priority_map = {"P1": "1", "P2": "2", "P3": "3", "P4": "4"}
            steps_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(remediation_steps))

            payload = {
                "short_description": title,
                "description": (
                    f"VulnPilot AI - Automated Remediation Ticket\n\n"
                    f"CVE: {cve_id}\n"
                    f"VPRS Score: {vprs_score}/100\n"
                    f"Priority: {priority}\n"
                    f"SLA: {sla_hours} hours\n\n"
                    f"Justification:\n{justification}\n\n"
                    f"Remediation Steps:\n{steps_text}\n\n"
                    f"Full Details:\n{description}"
                ),
                "priority": priority_map.get(priority, "3"),
                "urgency": priority_map.get(priority, "3"),
                "impact": priority_map.get(priority, "3"),
                "assigned_to": assigned_to,
                "category": "Security",
                "subcategory": "Vulnerability",
                "contact_type": "Automated",
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self._url(self.table),
                    auth=self._auth(),
                    json=payload,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )
                resp.raise_for_status()
                result = resp.json().get("result", {})

                ticket_number = result.get("number", "")
                sys_id = result.get("sys_id", "")

                logger.info(f"ServiceNow ticket created: {ticket_number} for {cve_id}")

                return TicketResult(
                    ticket_id=sys_id,
                    ticket_url=f"{self.instance}/nav_to.do?uri=incident.do?sys_id={sys_id}",
                    provider="servicenow",
                    assigned_to=assigned_to,
                    sla_deadline=datetime.utcnow() + timedelta(hours=sla_hours),
                    sla_hours=sla_hours,
                )
        except Exception as e:
            logger.error(f"ServiceNow ticket creation failed: {e}")
            return TicketResult(ticket_id="", provider="servicenow", success=False, error=str(e))

    async def check_sla(self, ticket_id: str) -> SLACheckResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self._url(f"{self.table}/{ticket_id}"),
                    auth=self._auth(),
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                ticket = resp.json().get("result", {})

                state = ticket.get("state", "1")
                state_map = {"1": "open", "2": "in_progress", "3": "in_progress",
                            "6": "resolved", "7": "closed"}

                return SLACheckResult(
                    ticket_id=ticket_id,
                    status=SLAStatusEnum.ON_TRACK,  # Would need SLA task query for real check
                    hours_remaining=0,
                    percent_elapsed=0,
                    needs_nudge=False,
                    needs_escalation=False,
                    current_ticket_status=state_map.get(state, "open"),
                )
        except Exception as e:
            logger.error(f"ServiceNow SLA check failed: {e}")
            return SLACheckResult(
                ticket_id=ticket_id, status=SLAStatusEnum.ON_TRACK,
                hours_remaining=0, percent_elapsed=0,
                needs_nudge=False, needs_escalation=False, current_ticket_status="unknown")

    async def update_ticket(self, ticket_id: str, **kwargs) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.patch(
                    self._url(f"{self.table}/{ticket_id}"),
                    auth=self._auth(), json=kwargs,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error(f"ServiceNow update failed: {e}")
            return False

    async def add_comment(self, ticket_id: str, comment: str) -> bool:
        return await self.update_ticket(ticket_id, comments=comment)

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    self._url(f"{self.table}?sysparm_limit=1"),
                    auth=self._auth(),
                    headers={"Accept": "application/json"},
                )
                return resp.status_code == 200
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "servicenow"
