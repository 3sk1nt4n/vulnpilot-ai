"""
VulnPilot AI - NVD/NIST CVE Enrichment
Free public API: https://services.nvd.nist.gov/rest/json/cves/2.0
Enriches vulnerabilities with official NIST data: CWE, references, 
affected configurations, and CVSS vectors.

Rate limit: 5 requests per 30 seconds (without API key)
           50 requests per 30 seconds (with free API key from https://nvd.nist.gov/developers/request-an-api-key)
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class NVDEnrichment:
    """Enrichment data from NVD/NIST for a single CVE."""
    cve_id: str
    found: bool = False

    # --- Official CVSS ---
    cvss_v31_score: float = 0.0
    cvss_v31_vector: str = ""
    cvss_v31_severity: str = ""

    # --- Weakness (CWE) ---
    cwe_ids: list[str] = field(default_factory=list)
    cwe_names: list[str] = field(default_factory=list)

    # --- Description ---
    description: str = ""

    # --- References (patches, advisories, exploits) ---
    references: list[dict] = field(default_factory=list)
    has_exploit_ref: bool = False         # Any reference tagged "Exploit"
    has_patch_ref: bool = False           # Any reference tagged "Patch"

    # --- Affected Configurations (CPE) ---
    affected_products: list[str] = field(default_factory=list)

    # --- Dates ---
    published: Optional[str] = None
    last_modified: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "found": self.found,
            "cvss_v31_score": self.cvss_v31_score,
            "cvss_v31_severity": self.cvss_v31_severity,
            "cwe_ids": self.cwe_ids,
            "description": self.description[:500],
            "has_exploit_ref": self.has_exploit_ref,
            "has_patch_ref": self.has_patch_ref,
            "affected_products": self.affected_products[:10],
            "published": self.published,
        }


class NVDClient:
    """Client for the NVD/NIST CVE 2.0 API (free, public)."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.api_key = os.getenv("NVD_API_KEY", "")  # Optional, increases rate limit
        self.timeout = 30.0
        self._cache: dict[str, NVDEnrichment] = {}
        # Rate limiting: 5 req/30s without key, 50 req/30s with key
        self._delay = 0.6 if not self.api_key else 0.06

    async def enrich(self, cve_id: str) -> NVDEnrichment:
        """Fetch full CVE details from NVD."""
        if cve_id in self._cache:
            return self._cache[cve_id]

        result = NVDEnrichment(cve_id=cve_id)

        try:
            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self.BASE_URL,
                    params={"cveId": cve_id},
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                logger.debug(f"NVD: {cve_id} not found")
                self._cache[cve_id] = result
                return result

            cve_data = vulns[0].get("cve", {})
            result.found = True

            # --- Description ---
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    result.description = desc.get("value", "")
                    break

            # --- CVSS v3.1 ---
            metrics = cve_data.get("metrics", {})
            for cvss31 in metrics.get("cvssMetricV31", []):
                cvss_data = cvss31.get("cvssData", {})
                result.cvss_v31_score = float(cvss_data.get("baseScore", 0))
                result.cvss_v31_vector = cvss_data.get("vectorString", "")
                result.cvss_v31_severity = cvss_data.get("baseSeverity", "")
                break  # Take the first (primary) score

            # Fallback to v3.0
            if result.cvss_v31_score == 0:
                for cvss30 in metrics.get("cvssMetricV30", []):
                    cvss_data = cvss30.get("cvssData", {})
                    result.cvss_v31_score = float(cvss_data.get("baseScore", 0))
                    result.cvss_v31_vector = cvss_data.get("vectorString", "")
                    result.cvss_v31_severity = cvss_data.get("baseSeverity", "")
                    break

            # --- CWE ---
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    cwe_val = desc.get("value", "")
                    if cwe_val.startswith("CWE-"):
                        result.cwe_ids.append(cwe_val)

            # --- References ---
            for ref in cve_data.get("references", []):
                ref_entry = {
                    "url": ref.get("url", ""),
                    "source": ref.get("source", ""),
                    "tags": ref.get("tags", []),
                }
                result.references.append(ref_entry)
                tags = ref.get("tags", [])
                if "Exploit" in tags:
                    result.has_exploit_ref = True
                if "Patch" in tags:
                    result.has_patch_ref = True

            # --- Affected Products (CPE) ---
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe = match.get("criteria", "")
                        if cpe:
                            # Extract readable product name from CPE string
                            # cpe:2.3:a:vendor:product:version:...
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 and parts[5] != "*" else "all versions"
                                result.affected_products.append(
                                    f"{vendor}/{product} ({version})"
                                )

            # --- Dates ---
            result.published = cve_data.get("published", "")[:10]
            result.last_modified = cve_data.get("lastModified", "")[:10]

            logger.debug(f"NVD enriched: {cve_id} - CVSS {result.cvss_v31_score}, "
                        f"CWE: {result.cwe_ids}, exploit_ref: {result.has_exploit_ref}")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.warning(f"NVD rate limited for {cve_id}. Consider getting a free API key.")
            else:
                logger.warning(f"NVD API error for {cve_id}: {e}")
        except Exception as e:
            logger.warning(f"NVD enrichment failed for {cve_id}: {e}")

        # Rate limit compliance
        await asyncio.sleep(self._delay)

        self._cache[cve_id] = result
        return result

    async def enrich_batch(self, cve_ids: list[str]) -> dict[str, NVDEnrichment]:
        """Enrich multiple CVEs (respects rate limits)."""
        results = {}
        for cve_id in cve_ids:
            results[cve_id] = await self.enrich(cve_id)
        return results

    def clear_cache(self):
        self._cache.clear()
