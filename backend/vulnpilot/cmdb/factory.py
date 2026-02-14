"""
VulnPilot AI - CMDB Provider Factory
CMDB_PROVIDER=csv          → Local CSV/JSON file ($0)
CMDB_PROVIDER=servicenow   → ServiceNow CMDB API
"""

import os
from functools import lru_cache
from vulnpilot.cmdb.provider import CMDBProvider


@lru_cache()
def get_cmdb_provider() -> CMDBProvider:
    provider = os.getenv("CMDB_PROVIDER", "csv").lower()

    if provider == "csv":
        from vulnpilot.cmdb.provider import CSVCMDBProvider
        return CSVCMDBProvider()
    elif provider == "servicenow":
        from vulnpilot.cmdb.provider import ServiceNowCMDBProvider
        return ServiceNowCMDBProvider()
    else:
        raise ValueError(f"Unknown CMDB_PROVIDER: '{provider}'. Must be 'csv' or 'servicenow'.")
