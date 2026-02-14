"""
VulnPilot AI - CMDB Provider
Asset inventory integration. Enriches vulnerabilities with:
  - Asset tier (tier_1/tier_2/tier_3)
  - Owner (person/team responsible)
  - Business unit
  - Network zone (internet-facing, DMZ, internal, segmented)
  - Compensating controls (WAF, IPS, segmentation)

Three modes:
  CMDB_PROVIDER=csv       → Import from CSV/JSON file ($0, local dev)
  CMDB_PROVIDER=servicenow → ServiceNow CMDB API (production)
  CMDB_PROVIDER=api       → Generic REST API (custom CMDB)
"""

import csv
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AssetRecord:
    """Normalized asset record from any CMDB source."""
    hostname: str = ""
    ip_address: str = ""

    # --- Classification ---
    asset_tier: str = "tier_3"             # tier_1 (crown jewel), tier_2, tier_3
    business_unit: str = ""
    environment: str = ""                   # production, staging, development
    asset_type: str = ""                    # server, workstation, network_device, database

    # --- Ownership ---
    owner: str = ""                         # Individual or team
    owner_email: str = ""
    escalation_contact: str = ""
    escalation_email: str = ""

    # --- Network Context ---
    is_internet_facing: bool = False
    network_zone: str = "internal"          # internet, dmz, internal, segmented, air_gapped
    vlan: str = ""
    subnet: str = ""

    # --- Compensating Controls ---
    has_waf: bool = False
    has_ips: bool = False
    is_segmented: bool = False
    has_edr: bool = False

    # --- Metadata ---
    os: str = ""
    last_scan_date: str = ""
    cmdb_id: str = ""                       # Source system ID
    tags: list[str] = field(default_factory=list)


class CMDBProvider(ABC):
    """Abstract CMDB provider. All sources normalize to AssetRecord."""

    @abstractmethod
    async def lookup_by_ip(self, ip_address: str) -> Optional[AssetRecord]:
        """Look up an asset by IP address."""
        ...

    @abstractmethod
    async def lookup_by_hostname(self, hostname: str) -> Optional[AssetRecord]:
        """Look up an asset by hostname."""
        ...

    @abstractmethod
    async def get_all_assets(self) -> list[AssetRecord]:
        """Get all assets from CMDB."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        ...

    async def enrich_vuln(self, hostname: str, ip_address: str) -> Optional[AssetRecord]:
        """Look up asset by hostname first, fall back to IP."""
        if hostname:
            record = await self.lookup_by_hostname(hostname)
            if record:
                return record
        if ip_address:
            return await self.lookup_by_ip(ip_address)
        return None


class CSVCMDBProvider(CMDBProvider):
    """Local CMDB from CSV or JSON file. Free, zero dependencies.

    CSV format:
      hostname,ip_address,asset_tier,business_unit,owner,owner_email,
      is_internet_facing,network_zone,has_waf,has_ips,is_segmented,environment

    JSON format:
      [{"hostname": "...", "ip_address": "...", "asset_tier": "tier_1", ...}]
    """

    def __init__(self):
        self.file_path = os.getenv("CMDB_FILE_PATH", "./data/cmdb_assets.csv")
        self._by_ip: dict[str, AssetRecord] = {}
        self._by_hostname: dict[str, AssetRecord] = {}
        self._loaded = False

    def _load(self):
        if self._loaded:
            return

        path = self.file_path
        if not os.path.exists(path):
            logger.warning(f"CMDB file not found: {path}")
            self._loaded = True
            return

        try:
            if path.endswith(".json"):
                self._load_json(path)
            else:
                self._load_csv(path)
            self._loaded = True
            logger.info(
                f"CMDB loaded: {len(self._by_ip)} IPs, "
                f"{len(self._by_hostname)} hostnames from {path}"
            )
        except Exception as e:
            logger.error(f"Failed to load CMDB file {path}: {e}")
            self._loaded = True

    def _load_csv(self, path: str):
        with open(path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                record = AssetRecord(
                    hostname=row.get("hostname", "").strip(),
                    ip_address=row.get("ip_address", "").strip(),
                    asset_tier=row.get("asset_tier", "tier_3").strip(),
                    business_unit=row.get("business_unit", "").strip(),
                    environment=row.get("environment", "").strip(),
                    asset_type=row.get("asset_type", "").strip(),
                    owner=row.get("owner", "").strip(),
                    owner_email=row.get("owner_email", "").strip(),
                    escalation_contact=row.get("escalation_contact", "").strip(),
                    escalation_email=row.get("escalation_email", "").strip(),
                    is_internet_facing=row.get("is_internet_facing", "").lower() in ("true", "1", "yes"),
                    network_zone=row.get("network_zone", "internal").strip(),
                    has_waf=row.get("has_waf", "").lower() in ("true", "1", "yes"),
                    has_ips=row.get("has_ips", "").lower() in ("true", "1", "yes"),
                    is_segmented=row.get("is_segmented", "").lower() in ("true", "1", "yes"),
                    has_edr=row.get("has_edr", "").lower() in ("true", "1", "yes"),
                    os=row.get("os", "").strip(),
                    cmdb_id=row.get("cmdb_id", "").strip(),
                )
                self._index_record(record)

    def _load_json(self, path: str):
        with open(path, "r") as f:
            data = json.load(f)
            assets = data if isinstance(data, list) else data.get("assets", [])
            for item in assets:
                record = AssetRecord(
                    hostname=item.get("hostname", ""),
                    ip_address=item.get("ip_address", ""),
                    asset_tier=item.get("asset_tier", "tier_3"),
                    business_unit=item.get("business_unit", ""),
                    environment=item.get("environment", ""),
                    asset_type=item.get("asset_type", ""),
                    owner=item.get("owner", ""),
                    owner_email=item.get("owner_email", ""),
                    escalation_contact=item.get("escalation_contact", ""),
                    escalation_email=item.get("escalation_email", ""),
                    is_internet_facing=bool(item.get("is_internet_facing", False)),
                    network_zone=item.get("network_zone", "internal"),
                    has_waf=bool(item.get("has_waf", False)),
                    has_ips=bool(item.get("has_ips", False)),
                    is_segmented=bool(item.get("is_segmented", False)),
                    has_edr=bool(item.get("has_edr", False)),
                    os=item.get("os", ""),
                    cmdb_id=item.get("cmdb_id", ""),
                    tags=item.get("tags", []),
                )
                self._index_record(record)

    def _index_record(self, record: AssetRecord):
        if record.ip_address:
            self._by_ip[record.ip_address] = record
        if record.hostname:
            self._by_hostname[record.hostname.lower()] = record

    async def lookup_by_ip(self, ip_address: str) -> Optional[AssetRecord]:
        self._load()
        return self._by_ip.get(ip_address)

    async def lookup_by_hostname(self, hostname: str) -> Optional[AssetRecord]:
        self._load()
        return self._by_hostname.get(hostname.lower())

    async def get_all_assets(self) -> list[AssetRecord]:
        self._load()
        seen = set()
        all_assets = []
        for record in list(self._by_ip.values()) + list(self._by_hostname.values()):
            key = f"{record.hostname}:{record.ip_address}"
            if key not in seen:
                seen.add(key)
                all_assets.append(record)
        return all_assets

    async def health_check(self) -> bool:
        return os.path.exists(self.file_path)

    @property
    def provider_name(self) -> str:
        return "csv"


class ServiceNowCMDBProvider(CMDBProvider):
    """ServiceNow CMDB integration via Table API.
    Queries cmdb_ci_server and cmdb_ci_ip_address tables.
    """

    def __init__(self):
        self.instance = os.getenv("SERVICENOW_INSTANCE", "")
        self.username = os.getenv("SERVICENOW_USERNAME", "")
        self.password = os.getenv("SERVICENOW_PASSWORD", "")
        self.timeout = 30.0
        self._cache: dict[str, AssetRecord] = {}

    async def lookup_by_ip(self, ip_address: str) -> Optional[AssetRecord]:
        if ip_address in self._cache:
            return self._cache[ip_address]

        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.instance}/api/now/table/cmdb_ci_server",
                    auth=(self.username, self.password),
                    params={
                        "sysparm_query": f"ip_address={ip_address}",
                        "sysparm_limit": 1,
                        "sysparm_fields": (
                            "sys_id,name,ip_address,os,sys_class_name,"
                            "u_asset_tier,u_business_unit,u_environment,"
                            "assigned_to,u_owner_email,u_escalation_contact,"
                            "u_is_internet_facing,u_network_zone,"
                            "u_has_waf,u_has_ips,u_is_segmented"
                        ),
                    },
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                results = resp.json().get("result", [])
                if results:
                    record = self._normalize_snow_record(results[0])
                    self._cache[ip_address] = record
                    return record
        except Exception as e:
            logger.warning(f"ServiceNow CMDB lookup failed for {ip_address}: {e}")
        return None

    async def lookup_by_hostname(self, hostname: str) -> Optional[AssetRecord]:
        if hostname.lower() in self._cache:
            return self._cache[hostname.lower()]

        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.instance}/api/now/table/cmdb_ci_server",
                    auth=(self.username, self.password),
                    params={
                        "sysparm_query": f"name={hostname}",
                        "sysparm_limit": 1,
                        "sysparm_fields": (
                            "sys_id,name,ip_address,os,sys_class_name,"
                            "u_asset_tier,u_business_unit,u_environment,"
                            "assigned_to,u_owner_email,u_escalation_contact,"
                            "u_is_internet_facing,u_network_zone,"
                            "u_has_waf,u_has_ips,u_is_segmented"
                        ),
                    },
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                results = resp.json().get("result", [])
                if results:
                    record = self._normalize_snow_record(results[0])
                    self._cache[hostname.lower()] = record
                    return record
        except Exception as e:
            logger.warning(f"ServiceNow CMDB lookup failed for {hostname}: {e}")
        return None

    def _normalize_snow_record(self, r: dict) -> AssetRecord:
        return AssetRecord(
            hostname=r.get("name", ""),
            ip_address=r.get("ip_address", ""),
            asset_tier=r.get("u_asset_tier", "tier_3"),
            business_unit=r.get("u_business_unit", ""),
            environment=r.get("u_environment", ""),
            asset_type=r.get("sys_class_name", ""),
            owner=r.get("assigned_to", {}).get("display_value", "") if isinstance(r.get("assigned_to"), dict) else r.get("assigned_to", ""),
            owner_email=r.get("u_owner_email", ""),
            escalation_contact=r.get("u_escalation_contact", ""),
            is_internet_facing=r.get("u_is_internet_facing", "false").lower() == "true",
            network_zone=r.get("u_network_zone", "internal"),
            has_waf=r.get("u_has_waf", "false").lower() == "true",
            has_ips=r.get("u_has_ips", "false").lower() == "true",
            is_segmented=r.get("u_is_segmented", "false").lower() == "true",
            os=r.get("os", ""),
            cmdb_id=r.get("sys_id", ""),
        )

    async def get_all_assets(self) -> list[AssetRecord]:
        results = []
        try:
            import httpx
            offset = 0
            limit = 500
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                while True:
                    resp = await client.get(
                        f"{self.instance}/api/now/table/cmdb_ci_server",
                        auth=(self.username, self.password),
                        params={"sysparm_limit": limit, "sysparm_offset": offset},
                        headers={"Accept": "application/json"},
                    )
                    resp.raise_for_status()
                    records = resp.json().get("result", [])
                    if not records:
                        break
                    for r in records:
                        results.append(self._normalize_snow_record(r))
                    offset += limit
        except Exception as e:
            logger.error(f"ServiceNow CMDB bulk fetch failed: {e}")
        return results

    async def health_check(self) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self.instance}/api/now/table/cmdb_ci_server?sysparm_limit=1",
                    auth=(self.username, self.password),
                    headers={"Accept": "application/json"},
                )
                return resp.status_code == 200
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "servicenow_cmdb"
