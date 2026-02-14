"""
VulnPilot AI - Scanner Provider Factory
Supports MULTIPLE simultaneous scanners (scanner-agnostic architecture).
SCANNER_PROVIDERS=tenable,qualys → ingests from both at once.
"""

import os
import logging
from vulnpilot.scanners.base import ScannerProvider

logger = logging.getLogger(__name__)

SCANNER_REGISTRY = {
    "tenable": "vulnpilot.scanners.tenable.TenableProvider",
    "qualys": "vulnpilot.scanners.qualys.QualysProvider",
    "rapid7": "vulnpilot.scanners.rapid7.Rapid7Provider",
    "openvas": "vulnpilot.scanners.openvas.OpenVASProvider",
    "wazuh": "vulnpilot.scanners.wazuh.WazuhProvider",
    "nessus_file": "vulnpilot.scanners.nessus_file.NessusFileProvider",
    "cloud": "vulnpilot.cloud.scanner_provider.CloudScannerProvider",
}


def _import_class(dotted_path: str):
    module_path, class_name = dotted_path.rsplit(".", 1)
    import importlib
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def get_scanner_providers() -> list[ScannerProvider]:
    """Factory: returns all configured scanner providers.

    SCANNER_PROVIDERS=tenable,qualys,rapid7  → 3 providers
    SCANNER_PROVIDERS=openvas                → 1 provider (free, point-in-time scanning)
    SCANNER_PROVIDERS=openvas,wazuh           → 2 providers (free, scheduled + continuous real-time)
    SCANNER_PROVIDERS=tenable,wazuh           → Commercial + real-time (recommended enterprise)
    """
    raw = os.getenv("SCANNER_PROVIDERS", "nessus_file")
    names = [s.strip().lower() for s in raw.split(",") if s.strip()]
    providers = []

    for name in names:
        if name not in SCANNER_REGISTRY:
            logger.warning(f"Unknown scanner provider: '{name}'. "
                          f"Available: {list(SCANNER_REGISTRY.keys())}")
            continue
        try:
            cls = _import_class(SCANNER_REGISTRY[name])
            providers.append(cls())
            logger.info(f"Scanner provider loaded: {name}")
        except Exception as e:
            logger.error(f"Failed to load scanner provider '{name}': {e}")

    if not providers:
        logger.warning("No scanner providers loaded! Check SCANNER_PROVIDERS env var.")

    return providers
