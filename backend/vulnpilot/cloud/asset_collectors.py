"""
VulnPilot AI - Cloud Asset Collectors
Direct API calls for cloud asset inventory (no AWS Config dependency).

Each collector builds an asset inventory that feeds into VPRS scoring:
  - Asset tier assignment (tier_1/tier_2/tier_3)
  - Internet-facing detection
  - Compensating controls (WAF, IPS, segmentation)
  - Owner/team mapping from cloud tags

Supports: AWS (boto3), Azure (azure-identity + azure-mgmt), GCP (google-cloud)
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CloudAsset:
    """Normalized cloud asset for VPRS enrichment."""
    asset_id: str                    # ARN, Azure resource ID, or GCP resource name
    cloud_provider: str              # aws, azure, gcp
    resource_type: str               # EC2, RDS, S3, VM, Storage, etc.
    name: str = ""
    ip_address: str = ""
    private_ip: str = ""
    hostname: str = ""
    region: str = ""
    account_id: str = ""
    tags: dict = field(default_factory=dict)
    # VPRS enrichment
    asset_tier: str = "tier_3"       # Derived from tags or naming convention
    is_internet_facing: bool = False
    has_waf: bool = False
    has_security_group: bool = False
    owner: str = ""
    business_unit: str = ""


class AWSCollector:
    """Collect AWS asset inventory via boto3 direct API calls.
    
    No AWS Config dependency. Uses describe_* APIs directly.
    Requires: IAM role with ReadOnlyAccess or specific describe permissions.
    """

    def __init__(self):
        self.region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.role_arn = os.getenv("AWS_PROWLER_ROLE_ARN", "")
        self.profile = os.getenv("AWS_PROFILE", "")
        self._session = None

    def _get_session(self):
        if self._session:
            return self._session
        try:
            import boto3
        except ImportError:
            raise RuntimeError("boto3 not installed. Run: pip install boto3")

        if self.role_arn:
            # Cross-account: assume role via STS
            sts = boto3.client("sts")
            creds = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="VulnPilotScan",
                DurationSeconds=3600,
            )["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        elif self.profile:
            self._session = boto3.Session(profile_name=self.profile, region_name=self.region)
        else:
            self._session = boto3.Session(region_name=self.region)
        return self._session

    async def collect_all(self, regions: list[str] = None) -> list[CloudAsset]:
        """Collect all AWS assets across specified regions."""
        if not regions:
            regions = [self.region]
        
        all_assets = []
        for region in regions:
            try:
                all_assets.extend(await self._collect_ec2(region))
                all_assets.extend(await self._collect_rds(region))
                all_assets.extend(await self._collect_s3(region))
                all_assets.extend(await self._collect_lambda(region))
                all_assets.extend(await self._collect_elb(region))
            except Exception as e:
                logger.error(f"AWS collection failed for {region}: {e}")

        logger.info(f"AWS: collected {len(all_assets)} assets across {len(regions)} regions")
        return all_assets

    async def _collect_ec2(self, region: str) -> list[CloudAsset]:
        session = self._get_session()
        ec2 = session.client("ec2", region_name=region)
        assets = []
        try:
            pages = ec2.get_paginator("describe_instances").paginate()
            for page in pages:
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        if inst.get("State", {}).get("Name") != "running":
                            continue
                        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                        public_ip = inst.get("PublicIpAddress", "")
                        assets.append(CloudAsset(
                            asset_id=inst["InstanceId"],
                            cloud_provider="aws", resource_type="EC2",
                            name=tags.get("Name", inst["InstanceId"]),
                            ip_address=public_ip,
                            private_ip=inst.get("PrivateIpAddress", ""),
                            region=region,
                            account_id=res.get("OwnerId", ""),
                            tags=tags,
                            is_internet_facing=bool(public_ip),
                            asset_tier=self._derive_tier(tags),
                            owner=tags.get("Owner", tags.get("owner", "")),
                            business_unit=tags.get("BusinessUnit", tags.get("Team", "")),
                        ))
        except Exception as e:
            logger.warning(f"EC2 collection failed ({region}): {e}")
        return assets

    async def _collect_rds(self, region: str) -> list[CloudAsset]:
        session = self._get_session()
        rds = session.client("rds", region_name=region)
        assets = []
        try:
            pages = rds.get_paginator("describe_db_instances").paginate()
            for page in pages:
                for db in page.get("DBInstances", []):
                    tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
                    assets.append(CloudAsset(
                        asset_id=db["DBInstanceArn"],
                        cloud_provider="aws", resource_type="RDS",
                        name=db["DBInstanceIdentifier"],
                        hostname=db.get("Endpoint", {}).get("Address", ""),
                        region=region, tags=tags,
                        is_internet_facing=db.get("PubliclyAccessible", False),
                        asset_tier=self._derive_tier(tags, default="tier_1"),  # DBs default tier_1
                        owner=tags.get("Owner", ""),
                        business_unit=tags.get("BusinessUnit", ""),
                    ))
        except Exception as e:
            logger.warning(f"RDS collection failed ({region}): {e}")
        return assets

    async def _collect_s3(self, region: str) -> list[CloudAsset]:
        if region != self.region:  # S3 is global, only collect once
            return []
        session = self._get_session()
        s3 = session.client("s3")
        assets = []
        try:
            for bucket in s3.list_buckets().get("Buckets", []):
                name = bucket["Name"]
                try:
                    tags_resp = s3.get_bucket_tagging(Bucket=name)
                    tags = {t["Key"]: t["Value"] for t in tags_resp.get("TagSet", [])}
                except Exception:
                    tags = {}
                # Check public access
                is_public = False
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    is_public = not all([
                        config.get("BlockPublicAcls", False),
                        config.get("BlockPublicPolicy", False),
                    ])
                except Exception:
                    pass
                assets.append(CloudAsset(
                    asset_id=f"arn:aws:s3:::{name}",
                    cloud_provider="aws", resource_type="S3",
                    name=name, region="global", tags=tags,
                    is_internet_facing=is_public,
                    asset_tier=self._derive_tier(tags),
                    owner=tags.get("Owner", ""),
                ))
        except Exception as e:
            logger.warning(f"S3 collection failed: {e}")
        return assets

    async def _collect_lambda(self, region: str) -> list[CloudAsset]:
        session = self._get_session()
        lam = session.client("lambda", region_name=region)
        assets = []
        try:
            pages = lam.get_paginator("list_functions").paginate()
            for page in pages:
                for fn in page.get("Functions", []):
                    tags = fn.get("Tags", {}) or {}
                    assets.append(CloudAsset(
                        asset_id=fn["FunctionArn"],
                        cloud_provider="aws", resource_type="Lambda",
                        name=fn["FunctionName"], region=region, tags=tags,
                        is_internet_facing=True,  # Lambda is always invocable
                        asset_tier=self._derive_tier(tags),
                        owner=tags.get("Owner", ""),
                    ))
        except Exception as e:
            logger.warning(f"Lambda collection failed ({region}): {e}")
        return assets

    async def _collect_elb(self, region: str) -> list[CloudAsset]:
        session = self._get_session()
        elbv2 = session.client("elbv2", region_name=region)
        assets = []
        try:
            pages = elbv2.get_paginator("describe_load_balancers").paginate()
            for page in pages:
                for lb in page.get("LoadBalancers", []):
                    scheme = lb.get("Scheme", "")
                    assets.append(CloudAsset(
                        asset_id=lb["LoadBalancerArn"],
                        cloud_provider="aws", resource_type="ELB",
                        name=lb["LoadBalancerName"],
                        hostname=lb.get("DNSName", ""),
                        region=region,
                        is_internet_facing=(scheme == "internet-facing"),
                        has_waf=False,  # Would need WAF API check
                        asset_tier="tier_1" if scheme == "internet-facing" else "tier_2",
                    ))
        except Exception as e:
            logger.warning(f"ELB collection failed ({region}): {e}")
        return assets

    @staticmethod
    def _derive_tier(tags: dict, default: str = "tier_3") -> str:
        """Derive asset tier from cloud tags."""
        tier_tag = tags.get("AssetTier", tags.get("asset_tier",
                    tags.get("Tier", tags.get("tier", ""))))
        if tier_tag:
            t = tier_tag.lower().replace("-", "_").replace(" ", "_")
            if t in ("tier_1", "tier1", "critical", "crown_jewel"):
                return "tier_1"
            if t in ("tier_2", "tier2", "important", "high"):
                return "tier_2"
            return "tier_3"

        # Heuristic: environment-based
        env = tags.get("Environment", tags.get("Env", tags.get("env", ""))).lower()
        if env in ("production", "prod", "prd"):
            return "tier_1"
        if env in ("staging", "stg", "uat", "preprod"):
            return "tier_2"
        return default


class AzureCollector:
    """Azure asset collector via Azure SDK.

    Requires: pip install azure-identity azure-mgmt-compute azure-mgmt-network azure-mgmt-storage
    Credentials: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID
    """

    def __init__(self):
        self.tenant_id = os.getenv("AZURE_TENANT_ID", "")
        self.client_id = os.getenv("AZURE_CLIENT_ID", "")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")

    def _get_credential(self):
        from azure.identity import ClientSecretCredential
        return ClientSecretCredential(self.tenant_id, self.client_id, self.client_secret)

    async def collect_all(self) -> list[CloudAsset]:
        if not all([self.tenant_id, self.client_id, self.client_secret, self.subscription_id]):
            logger.info("Azure: missing credentials, skipping collection")
            return []
        all_assets = []
        try:
            all_assets.extend(await self._collect_vms())
            all_assets.extend(await self._collect_storage())
            all_assets.extend(await self._collect_sql())
        except ImportError:
            logger.warning("Azure SDK not installed. Run: pip install azure-identity azure-mgmt-compute azure-mgmt-storage azure-mgmt-sql")
        except Exception as e:
            logger.error(f"Azure collection failed: {e}")
        logger.info(f"Azure: collected {len(all_assets)} assets")
        return all_assets

    async def _collect_vms(self) -> list[CloudAsset]:
        assets = []
        try:
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.network import NetworkManagementClient
            cred = self._get_credential()
            compute = ComputeManagementClient(cred, self.subscription_id)
            network = NetworkManagementClient(cred, self.subscription_id)

            # Cache public IPs
            public_ips = {}
            for ip in network.public_ip_addresses.list_all():
                if ip.ip_address:
                    public_ips[ip.id] = ip.ip_address

            for vm in compute.virtual_machines.list_all():
                tags = vm.tags or {}
                location = vm.location or ""
                # Get network info
                public_ip = ""
                private_ip = ""
                if vm.network_profile and vm.network_profile.network_interfaces:
                    for nic_ref in vm.network_profile.network_interfaces:
                        try:
                            rg = nic_ref.id.split("/")[4]
                            nic_name = nic_ref.id.split("/")[-1]
                            nic = network.network_interfaces.get(rg, nic_name)
                            for ip_config in (nic.ip_configurations or []):
                                if ip_config.private_ip_address:
                                    private_ip = ip_config.private_ip_address
                                if ip_config.public_ip_address and ip_config.public_ip_address.id in public_ips:
                                    public_ip = public_ips[ip_config.public_ip_address.id]
                        except Exception:
                            pass

                assets.append(CloudAsset(
                    asset_id=vm.id, cloud_provider="azure", resource_type="VM",
                    name=vm.name, ip_address=public_ip, private_ip=private_ip,
                    region=location, tags=tags,
                    is_internet_facing=bool(public_ip),
                    asset_tier=AWSCollector._derive_tier(tags),
                    owner=tags.get("Owner", tags.get("owner", "")),
                    business_unit=tags.get("BusinessUnit", tags.get("Department", "")),
                ))
        except Exception as e:
            logger.warning(f"Azure VM collection failed: {e}")
        return assets

    async def _collect_storage(self) -> list[CloudAsset]:
        assets = []
        try:
            from azure.mgmt.storage import StorageManagementClient
            cred = self._get_credential()
            storage = StorageManagementClient(cred, self.subscription_id)
            for acct in storage.storage_accounts.list():
                tags = acct.tags or {}
                is_public = acct.allow_blob_public_access if hasattr(acct, 'allow_blob_public_access') else False
                assets.append(CloudAsset(
                    asset_id=acct.id, cloud_provider="azure", resource_type="StorageAccount",
                    name=acct.name, region=acct.location or "", tags=tags,
                    is_internet_facing=bool(is_public),
                    asset_tier=AWSCollector._derive_tier(tags),
                    owner=tags.get("Owner", ""),
                ))
        except Exception as e:
            logger.warning(f"Azure Storage collection failed: {e}")
        return assets

    async def _collect_sql(self) -> list[CloudAsset]:
        assets = []
        try:
            from azure.mgmt.sql import SqlManagementClient
            cred = self._get_credential()
            sql = SqlManagementClient(cred, self.subscription_id)
            for server in sql.servers.list():
                tags = server.tags or {}
                assets.append(CloudAsset(
                    asset_id=server.id, cloud_provider="azure", resource_type="SQLServer",
                    name=server.name, hostname=getattr(server, 'fully_qualified_domain_name', ''),
                    region=server.location or "", tags=tags,
                    is_internet_facing=True,  # Azure SQL servers have public endpoints by default
                    asset_tier=AWSCollector._derive_tier(tags, default="tier_1"),
                    owner=tags.get("Owner", ""),
                ))
        except Exception as e:
            logger.warning(f"Azure SQL collection failed: {e}")
        return assets


class GCPCollector:
    """GCP asset collector via Google Cloud client libraries.

    Requires: pip install google-cloud-asset google-cloud-compute google-cloud-storage
    Credentials: GCP_PROJECT_ID + GOOGLE_APPLICATION_CREDENTIALS (SA key file)
    """

    def __init__(self):
        self.project_id = os.getenv("GCP_PROJECT_ID", "")

    async def collect_all(self) -> list[CloudAsset]:
        if not self.project_id:
            logger.info("GCP: missing GCP_PROJECT_ID, skipping collection")
            return []
        all_assets = []
        try:
            all_assets.extend(await self._collect_instances())
            all_assets.extend(await self._collect_gcs_buckets())
            all_assets.extend(await self._collect_sql_instances())
        except ImportError:
            logger.warning("GCP SDK not installed. Run: pip install google-cloud-compute google-cloud-storage google-cloud-sqladmin")
        except Exception as e:
            logger.error(f"GCP collection failed: {e}")
        logger.info(f"GCP: collected {len(all_assets)} assets")
        return all_assets

    async def _collect_instances(self) -> list[CloudAsset]:
        assets = []
        try:
            from google.cloud import compute_v1
            client = compute_v1.InstancesClient()
            # List instances across all zones via aggregated list
            request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
            for zone, response in client.aggregated_list(request=request):
                if response.instances:
                    for inst in response.instances:
                        if inst.status != "RUNNING":
                            continue
                        labels = dict(inst.labels) if inst.labels else {}
                        zone_name = zone.split("/")[-1] if "/" in zone else zone
                        # Get IPs
                        public_ip = ""
                        private_ip = ""
                        for iface in (inst.network_interfaces or []):
                            if iface.network_i_p:
                                private_ip = iface.network_i_p
                            for ac in (iface.access_configs or []):
                                if ac.nat_i_p:
                                    public_ip = ac.nat_i_p
                        assets.append(CloudAsset(
                            asset_id=f"projects/{self.project_id}/zones/{zone_name}/instances/{inst.name}",
                            cloud_provider="gcp", resource_type="ComputeInstance",
                            name=inst.name, ip_address=public_ip, private_ip=private_ip,
                            region=zone_name, tags=labels,
                            is_internet_facing=bool(public_ip),
                            asset_tier=AWSCollector._derive_tier(labels),
                            owner=labels.get("owner", ""),
                            business_unit=labels.get("team", labels.get("department", "")),
                        ))
        except Exception as e:
            logger.warning(f"GCP Compute collection failed: {e}")
        return assets

    async def _collect_gcs_buckets(self) -> list[CloudAsset]:
        assets = []
        try:
            from google.cloud import storage
            client = storage.Client(project=self.project_id)
            for bucket in client.list_buckets():
                labels = dict(bucket.labels) if bucket.labels else {}
                # Check public access
                is_public = False
                try:
                    policy = bucket.get_iam_policy()
                    for binding in policy.bindings:
                        if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                            is_public = True
                            break
                except Exception:
                    pass
                assets.append(CloudAsset(
                    asset_id=f"projects/{self.project_id}/buckets/{bucket.name}",
                    cloud_provider="gcp", resource_type="GCSBucket",
                    name=bucket.name, region=bucket.location or "global", tags=labels,
                    is_internet_facing=is_public,
                    asset_tier=AWSCollector._derive_tier(labels),
                    owner=labels.get("owner", ""),
                ))
        except Exception as e:
            logger.warning(f"GCP Storage collection failed: {e}")
        return assets

    async def _collect_sql_instances(self) -> list[CloudAsset]:
        assets = []
        try:
            from google.cloud.sql_v1 import SqlInstancesServiceClient
            client = SqlInstancesServiceClient()
            response = client.list(project=self.project_id)
            for inst in response.items:
                labels = dict(inst.settings.user_labels) if inst.settings and inst.settings.user_labels else {}
                public_ip = ""
                for addr in (inst.ip_addresses or []):
                    if addr.type_ == "PRIMARY":
                        public_ip = addr.ip_address
                assets.append(CloudAsset(
                    asset_id=f"projects/{self.project_id}/instances/{inst.name}",
                    cloud_provider="gcp", resource_type="CloudSQL",
                    name=inst.name, ip_address=public_ip,
                    region=inst.region or "", tags=labels,
                    is_internet_facing=bool(public_ip),
                    asset_tier=AWSCollector._derive_tier(labels, default="tier_1"),
                    owner=labels.get("owner", ""),
                ))
        except Exception as e:
            logger.warning(f"GCP Cloud SQL collection failed: {e}")
        return assets
