"""
VulnPilot AI - Ticket Provider Factory
TICKET_PROVIDER=console      → Dev mode ($0)
TICKET_PROVIDER=servicenow   → Enterprise production
TICKET_PROVIDER=jira         → Standard production
"""

import os
import logging
from functools import lru_cache
from vulnpilot.tickets.base import TicketProvider

logger = logging.getLogger(__name__)


@lru_cache()
def get_ticket_provider() -> TicketProvider:
    provider = os.getenv("TICKET_PROVIDER", "console").lower()

    if provider == "console":
        from vulnpilot.tickets.console import ConsoleProvider
        return ConsoleProvider()
    elif provider == "servicenow":
        from vulnpilot.tickets.servicenow import ServiceNowProvider
        return ServiceNowProvider()
    elif provider == "jira":
        from vulnpilot.tickets.jira_provider import JiraProvider
        return JiraProvider()
    elif provider == "pagerduty":
        from vulnpilot.tickets.pagerduty import PagerDutyProvider
        return PagerDutyProvider()
    else:
        raise ValueError(f"Unknown TICKET_PROVIDER: '{provider}'. "
                        f"Must be 'console', 'servicenow', 'jira', or 'pagerduty'.")
