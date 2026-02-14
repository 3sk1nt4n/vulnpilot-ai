"""
VulnPilot AI - Cloud Credential Manager
Secure credential handling for AWS, Azure, GCP cloud integrations.

Supports:
  AWS: IAM Access Keys, STS AssumeRole (cross-account), Instance Profile
  Azure: Service Principal (client_id + secret), Managed Identity
  GCP: Service Account Key, Workload Identity

Credentials are stored in-memory (env vars) - NOT persisted to disk.
For production: integrate with HashiCorp Vault, AWS Secrets Manager, etc.
"""

import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CloudCredential:
    """Validated cloud credential set."""
    provider: str           # aws, azure, gcp
    is_valid: bool = False
    account_id: str = ""
    account_name: str = ""
    error: str = ""
    method: str = ""        # access_key, assume_role, instance_profile, service_principal, sa_key


class CredentialManager:
    """Manages and validates cloud credentials for all providers."""

    async def validate_aws(self) -> CloudCredential:
        """Validate AWS credentials by calling STS GetCallerIdentity."""
        cred = CloudCredential(provider="aws")
        try:
            import boto3
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()
            cred.is_valid = True
            cred.account_id = identity.get("Account", "")
            cred.account_name = identity.get("Arn", "").split("/")[-1]
            # Detect auth method
            arn = identity.get("Arn", "")
            if "assumed-role" in arn:
                cred.method = "assume_role"
            elif "instance-profile" in arn:
                cred.method = "instance_profile"
            else:
                cred.method = "access_key"
            logger.info(f"AWS credentials valid: account={cred.account_id}, method={cred.method}")
        except ImportError:
            cred.error = "boto3 not installed"
        except Exception as e:
            cred.error = str(e)
            logger.warning(f"AWS credential validation failed: {e}")
        return cred

    async def validate_azure(self) -> CloudCredential:
        """Validate Azure credentials."""
        cred = CloudCredential(provider="azure")
        tenant_id = os.getenv("AZURE_TENANT_ID", "")
        client_id = os.getenv("AZURE_CLIENT_ID", "")
        client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")

        if not all([tenant_id, client_id, client_secret]):
            cred.error = "Missing AZURE_TENANT_ID, AZURE_CLIENT_ID, or AZURE_CLIENT_SECRET"
            return cred

        try:
            from azure.identity import ClientSecretCredential
            credential = ClientSecretCredential(tenant_id, client_id, client_secret)
            token = credential.get_token("https://management.azure.com/.default")
            if token:
                cred.is_valid = True
                cred.account_id = subscription_id
                cred.method = "service_principal"
                logger.info(f"Azure credentials valid: subscription={subscription_id}")
        except ImportError:
            cred.error = "azure-identity not installed"
        except Exception as e:
            cred.error = str(e)
            logger.warning(f"Azure credential validation failed: {e}")
        return cred

    async def validate_gcp(self) -> CloudCredential:
        """Validate GCP credentials."""
        cred = CloudCredential(provider="gcp")
        project_id = os.getenv("GCP_PROJECT_ID", "")
        sa_key = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")

        if not project_id:
            cred.error = "Missing GCP_PROJECT_ID"
            return cred

        try:
            from google.auth import default as google_default
            credentials, project = google_default()
            cred.is_valid = True
            cred.account_id = project or project_id
            cred.method = "service_account" if sa_key else "workload_identity"
            logger.info(f"GCP credentials valid: project={cred.account_id}")
        except ImportError:
            cred.error = "google-auth not installed"
        except Exception as e:
            cred.error = str(e)
            logger.warning(f"GCP credential validation failed: {e}")
        return cred

    async def validate_all(self) -> dict[str, CloudCredential]:
        """Validate all configured cloud credentials."""
        results = {}

        # AWS
        if any(os.getenv(k) for k in ["AWS_ACCESS_KEY_ID", "AWS_PROWLER_ROLE_ARN", "AWS_PROFILE"]):
            results["aws"] = await self.validate_aws()
        else:
            results["aws"] = CloudCredential(provider="aws", error="No AWS credentials configured")

        # Azure
        if os.getenv("AZURE_TENANT_ID"):
            results["azure"] = await self.validate_azure()
        else:
            results["azure"] = CloudCredential(provider="azure", error="No Azure credentials configured")

        # GCP
        if os.getenv("GCP_PROJECT_ID") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
            results["gcp"] = await self.validate_gcp()
        else:
            results["gcp"] = CloudCredential(provider="gcp", error="No GCP credentials configured")

        return results

    def get_env_template(self, provider: str) -> dict:
        """Return env var template for a cloud provider."""
        templates = {
            "aws": {
                "AWS_ACCESS_KEY_ID": "AKIA...",
                "AWS_SECRET_ACCESS_KEY": "your-secret-key",
                "AWS_DEFAULT_REGION": "us-east-1",
                "AWS_PROWLER_ROLE_ARN": "arn:aws:iam::123456789:role/ProwlerRole (optional, for cross-account)",
            },
            "azure": {
                "AZURE_TENANT_ID": "your-tenant-id",
                "AZURE_CLIENT_ID": "your-app-registration-client-id",
                "AZURE_CLIENT_SECRET": "your-client-secret",
                "AZURE_SUBSCRIPTION_ID": "your-subscription-id",
            },
            "gcp": {
                "GCP_PROJECT_ID": "your-project-id",
                "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/service-account-key.json",
            },
        }
        return templates.get(provider, {})
