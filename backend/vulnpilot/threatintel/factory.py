"""
VulnPilot AI - Threat Intel Provider Factory
THREATINTEL_MODE=local → Cached CSV/JSON ($0)
THREATINTEL_MODE=api   → Live EPSS/KEV/OTX/GreyNoise APIs
"""

import os
from functools import lru_cache
from vulnpilot.threatintel.base import ThreatIntelProvider


@lru_cache()
def get_threatintel_provider() -> ThreatIntelProvider:
    mode = os.getenv("THREATINTEL_MODE", "local").lower()

    if mode == "api":
        from vulnpilot.threatintel.api_provider import APIThreatIntelProvider
        return APIThreatIntelProvider()
    elif mode == "local":
        from vulnpilot.threatintel.local_provider import LocalThreatIntelProvider
        return LocalThreatIntelProvider()
    else:
        raise ValueError(f"Unknown THREATINTEL_MODE: '{mode}'. Must be 'local' or 'api'.")
