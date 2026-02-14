"""
VulnPilot AI - Central Configuration
Reads environment variables and provides typed settings.
The .env file is the SINGLE switch between local and cloud modes.
"""

import os
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Application ---
    app_name: str = "VulnPilot AI"
    app_env: Literal["development", "production", "testing"] = "development"
    log_level: str = "info"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    secret_key: str = "change-me-in-production"

    # --- LLM Provider ---
    llm_provider: Literal["ollama", "anthropic"] = "ollama"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.3:70b"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"

    # --- Scanner Providers (comma-separated) ---
    scanner_providers: str = "openvas,nessus_file"
    openvas_host: str = "localhost"
    openvas_port: int = 9390
    openvas_user: str = "admin"
    openvas_password: str = "admin"
    nessus_file_path: str = "./data/sample_scans/"
    tenable_access_key: str = ""
    tenable_secret_key: str = ""
    qualys_api_url: str = ""
    qualys_username: str = ""
    qualys_password: str = ""
    rapid7_api_key: str = ""
    rapid7_region: str = "us"

    # --- Ticket Provider ---
    ticket_provider: Literal[
        "console", "servicenow", "jira", "gitlab"
    ] = "console"
    servicenow_instance: str = ""
    servicenow_username: str = ""
    servicenow_password: str = ""
    jira_url: str = ""
    jira_username: str = ""
    jira_api_token: str = ""
    jira_project_key: str = "VULN"

    # --- Threat Intelligence ---
    threatintel_mode: Literal["local", "api"] = "local"
    epss_csv_path: str = "./data/epss_scores.csv"
    kev_json_path: str = "./data/known_exploited_vulns.json"
    otx_pulse_path: str = "./data/otx_pulses.json"
    otx_api_key: str = ""
    greynoise_api_key: str = ""

    # --- Database ---
    database_url: str = "postgresql+asyncpg://vulnpilot:dev@localhost:5432/vulnpilot"
    database_url_sync: str = "postgresql://vulnpilot:dev@localhost:5432/vulnpilot"

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- Auth ---
    auth_provider: Literal["none", "clerk", "keycloak"] = "none"
    clerk_secret_key: str = ""

    # --- VPRS Config Paths ---
    vprs_weights_path: str = "./config/vprs_weights.yaml"
    hard_rules_path: str = "./config/hard_rules.yaml"
    sla_tiers_path: str = "./config/sla_tiers.yaml"

    # --- Drift Detector ---
    drift_check_interval_hours: int = 6

    @property
    def scanner_provider_list(self) -> list[str]:
        """Parse comma-separated scanner providers."""
        return [s.strip() for s in self.scanner_providers.split(",") if s.strip()]

    @property
    def is_local_mode(self) -> bool:
        return self.llm_provider == "ollama"

    @property
    def is_cloud_mode(self) -> bool:
        return self.llm_provider == "anthropic"

    class Config:
        env_file = ".env.local"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
