"""
VulnPilot AI - Ticket Provider Interface (Layer 3)
Switch between ServiceNow, Jira, GitLab Issues, or console output.

TICKET_PROVIDER=console     → Dev mode (print to stdout)
TICKET_PROVIDER=servicenow  → Enterprise production
TICKET_PROVIDER=jira        → Standard production
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class SLAStatusEnum(str, Enum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    WARNING = "warning"
    BREACHED = "breached"


@dataclass
class TicketResult:
    """Result of creating a ticket in the external system."""
    ticket_id: str                 # External system's ticket ID
    ticket_url: str = ""           # Link to the ticket
    provider: str = ""             # servicenow, jira, console
    status: str = "open"
    assigned_to: str = ""
    sla_deadline: Optional[datetime] = None
    sla_hours: int = 0
    success: bool = True
    error: str = ""


@dataclass
class SLACheckResult:
    """Result of checking a ticket's SLA status."""
    ticket_id: str
    status: SLAStatusEnum
    hours_remaining: float
    percent_elapsed: float
    needs_nudge: bool              # > 50% elapsed
    needs_escalation: bool         # > 75% elapsed or breached
    current_ticket_status: str     # open, in_progress, resolved


class TicketProvider(ABC):
    """
    Abstract base class for ticket/remediation providers.
    Implementations: ServiceNowProvider, JiraProvider,
                     GitLabIssuesProvider, ConsoleProvider
    """

    @abstractmethod
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
        """Create a remediation ticket in the external system.

        Args:
            cve_id: CVE identifier
            title: Ticket title
            description: Full description with VPRS context
            priority: P1/P2/P3/P4
            assigned_to: Owner name or email
            sla_hours: SLA deadline in hours
            vprs_score: VPRS score for context
            justification: Plain-English justification
            remediation_steps: List of specific fix steps

        Returns:
            TicketResult with external ticket ID and URL
        """
        ...

    @abstractmethod
    async def check_sla(self, ticket_id: str) -> SLACheckResult:
        """Check a ticket's SLA compliance status.

        Returns:
            SLACheckResult with timing and escalation flags
        """
        ...

    @abstractmethod
    async def update_ticket(self, ticket_id: str, **kwargs) -> bool:
        """Update a ticket's fields (status, assignee, notes, etc.)."""
        ...

    @abstractmethod
    async def add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment/work note to a ticket (for nudges/escalations)."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the ticket system is reachable."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return provider name (e.g., 'servicenow', 'jira', 'console')."""
        ...
