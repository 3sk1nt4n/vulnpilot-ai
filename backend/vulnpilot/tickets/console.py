"""
VulnPilot AI - Console Ticket Provider
Dev mode: prints tickets to stdout instead of creating ServiceNow/Jira tickets.
Perfect for local development and testing. $0 cost.
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional

from vulnpilot.tickets.base import (
    TicketProvider, TicketResult, SLACheckResult, SLAStatusEnum
)

logger = logging.getLogger(__name__)

# In-memory ticket store for dev mode
_ticket_store: dict[str, dict] = {}


class ConsoleProvider(TicketProvider):
    """Dev-mode ticket provider - prints to stdout, tracks in memory."""

    async def create_ticket(
        self,
        cve_id: str,
        title: str,
        description: str,
        priority: str,
        assigned_to: str,
        sla_hours: int,
        vprs_score: float,
        justification: str,
        remediation_steps: list[str],
    ) -> TicketResult:
        ticket_id = f"VPAI-{str(uuid.uuid4())[:8].upper()}"
        deadline = datetime.utcnow() + timedelta(hours=sla_hours)

        # Store in memory
        _ticket_store[ticket_id] = {
            "ticket_id": ticket_id,
            "cve_id": cve_id,
            "title": title,
            "priority": priority,
            "assigned_to": assigned_to,
            "status": "open",
            "created_at": datetime.utcnow(),
            "sla_deadline": deadline,
            "sla_hours": sla_hours,
            "vprs_score": vprs_score,
        }

        # Pretty print
        steps_text = "\n".join(f"   {i+1}. {s}" for i, s in enumerate(remediation_steps))
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║  🎫 VULNPILOT TICKET CREATED                                ║
╠══════════════════════════════════════════════════════════════╣
║  ID:       {ticket_id:<48} ║
║  CVE:      {cve_id:<48} ║
║  VPRS:     {vprs_score:<48} ║
║  Priority: {priority:<48} ║
║  Assigned: {assigned_to:<48} ║
║  SLA:      {sla_hours}h (deadline: {deadline.isoformat()[:19]}){"":>10} ║
╠══════════════════════════════════════════════════════════════╣
║  Title: {title[:54]:<54} ║
╠══════════════════════════════════════════════════════════════╣
║  Justification:                                              ║
║  {justification[:58]:<58} ║
╠══════════════════════════════════════════════════════════════╣
║  Remediation Steps:                                          ║
{steps_text}
╚══════════════════════════════════════════════════════════════╝
""")
        logger.info(f"Console ticket created: {ticket_id} for {cve_id} (VPRS: {vprs_score})")

        return TicketResult(
            ticket_id=ticket_id,
            ticket_url=f"console://{ticket_id}",
            provider="console",
            assigned_to=assigned_to,
            sla_deadline=deadline,
            sla_hours=sla_hours,
        )

    async def check_sla(self, ticket_id: str) -> SLACheckResult:
        ticket = _ticket_store.get(ticket_id)
        if not ticket:
            return SLACheckResult(
                ticket_id=ticket_id,
                status=SLAStatusEnum.ON_TRACK,
                hours_remaining=0,
                percent_elapsed=0,
                needs_nudge=False,
                needs_escalation=False,
                current_ticket_status="unknown",
            )

        now = datetime.utcnow()
        elapsed = (now - ticket["created_at"]).total_seconds() / 3600
        total = ticket["sla_hours"]
        remaining = max(0, total - elapsed)
        pct = min(100, (elapsed / total) * 100) if total > 0 else 0

        if pct >= 100:
            status = SLAStatusEnum.BREACHED
        elif pct >= 75:
            status = SLAStatusEnum.WARNING
        elif pct >= 50:
            status = SLAStatusEnum.AT_RISK
        else:
            status = SLAStatusEnum.ON_TRACK

        return SLACheckResult(
            ticket_id=ticket_id,
            status=status,
            hours_remaining=round(remaining, 1),
            percent_elapsed=round(pct, 1),
            needs_nudge=pct >= 50,
            needs_escalation=pct >= 75,
            current_ticket_status=ticket.get("status", "open"),
        )

    async def update_ticket(self, ticket_id: str, **kwargs) -> bool:
        if ticket_id in _ticket_store:
            _ticket_store[ticket_id].update(kwargs)
            logger.info(f"Console ticket updated: {ticket_id} → {kwargs}")
            return True
        return False

    async def add_comment(self, ticket_id: str, comment: str) -> bool:
        logger.info(f"Console ticket comment [{ticket_id}]: {comment}")
        print(f"  💬 [{ticket_id}] {comment}")
        return True

    async def health_check(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "console"
