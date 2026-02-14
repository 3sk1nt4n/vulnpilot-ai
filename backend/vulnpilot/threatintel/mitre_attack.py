"""
VulnPilot AI - MITRE ATT&CK Mapping
Free public data: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

Maps CWE IDs (from NVD) to MITRE ATT&CK techniques and tactics.
Adds tactical context: "This vuln enables Initial Access via T1190 Exploit Public-Facing Application."

Also supports direct CVE→technique mapping from MITRE's capec-attack patterns.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# CWE → ATT&CK Technique mapping (most common mappings)
# Source: MITRE CWE→CAPEC→ATT&CK chain + manual curation
CWE_TO_ATTACK: dict[str, list[dict]] = {
    # Injection flaws
    "CWE-78": [{"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-79": [{"technique": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"}],
    "CWE-89": [{"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-94": [{"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],

    # Authentication / Access
    "CWE-287": [{"technique": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
                {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-306": [{"technique": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}],
    "CWE-522": [{"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    "CWE-798": [{"technique": "T1078.001", "name": "Default Accounts", "tactic": "Persistence"}],

    # Buffer / Memory
    "CWE-119": [{"technique": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-120": [{"technique": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-122": [{"technique": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-416": [{"technique": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-787": [{"technique": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],

    # Path Traversal / File
    "CWE-22": [{"technique": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
               {"technique": "T1005", "name": "Data from Local System", "tactic": "Collection"}],
    "CWE-434": [{"technique": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}],

    # Deserialization
    "CWE-502": [{"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
                {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],

    # SSRF
    "CWE-918": [{"technique": "T1090", "name": "Proxy", "tactic": "Command and Control"},
                {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],

    # Privilege Escalation
    "CWE-269": [{"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"}],
    "CWE-250": [{"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"}],

    # Information Disclosure
    "CWE-200": [{"technique": "T1005", "name": "Data from Local System", "tactic": "Collection"}],
    "CWE-532": [{"technique": "T1005", "name": "Data from Local System", "tactic": "Collection"}],

    # Race Condition (like regreSSHion CVE-2024-6387)
    "CWE-362": [{"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"}],

    # XXE
    "CWE-611": [{"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"technique": "T1005", "name": "Data from Local System", "tactic": "Collection"}],

    # Cryptographic
    "CWE-327": [{"technique": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
    "CWE-295": [{"technique": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
}

# Common CVE → ATT&CK direct mappings for high-profile vulns
CVE_TO_ATTACK: dict[str, list[dict]] = {
    "CVE-2024-21887": [
        {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"technique": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
    ],
    "CVE-2024-3400": [
        {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"technique": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "CVE-2024-1709": [
        {"technique": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
        {"technique": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
    ],
    "CVE-2023-34362": [
        {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    ],
    "CVE-2024-6387": [
        {"technique": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
        {"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
}


@dataclass
class ATTACKMapping:
    """MITRE ATT&CK mapping result for a CVE."""
    cve_id: str
    techniques: list[dict] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    mapped_from: str = ""  # "cve_direct", "cwe_mapping", "none"
    kill_chain_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "techniques": self.techniques,
            "tactics": sorted(set(self.tactics)),
            "mapped_from": self.mapped_from,
            "kill_chain_summary": self.kill_chain_summary,
        }


class MITREATTACKMapper:
    """Maps CVEs to MITRE ATT&CK techniques and tactics."""

    # Tactic ordering per the ATT&CK kill chain
    KILL_CHAIN_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    def map_cve(self, cve_id: str, cwe_ids: list[str] = None) -> ATTACKMapping:
        """Map a CVE to ATT&CK techniques.

        Priority:
        1. Direct CVE→ATT&CK mapping (high-profile vulns)
        2. CWE→ATT&CK mapping (general)
        3. No mapping available
        """
        result = ATTACKMapping(cve_id=cve_id)

        # 1. Direct CVE mapping
        if cve_id in CVE_TO_ATTACK:
            result.techniques = CVE_TO_ATTACK[cve_id]
            result.tactics = [t["tactic"] for t in result.techniques]
            result.mapped_from = "cve_direct"
            result.kill_chain_summary = self._build_kill_chain_summary(result.techniques)
            return result

        # 2. CWE-based mapping
        if cwe_ids:
            all_techniques = []
            seen = set()
            for cwe in cwe_ids:
                techniques = CWE_TO_ATTACK.get(cwe, [])
                for t in techniques:
                    key = t["technique"]
                    if key not in seen:
                        seen.add(key)
                        all_techniques.append(t)

            if all_techniques:
                result.techniques = all_techniques
                result.tactics = [t["tactic"] for t in all_techniques]
                result.mapped_from = "cwe_mapping"
                result.kill_chain_summary = self._build_kill_chain_summary(all_techniques)
                return result

        result.mapped_from = "none"
        return result

    def _build_kill_chain_summary(self, techniques: list[dict]) -> str:
        """Build a human-readable kill chain summary."""
        tactics = sorted(
            set(t["tactic"] for t in techniques),
            key=lambda x: self.KILL_CHAIN_ORDER.index(x) if x in self.KILL_CHAIN_ORDER else 99,
        )
        tech_strs = [f"{t['technique']} {t['name']}" for t in techniques]
        return (
            f"Kill chain: {' → '.join(tactics)}. "
            f"Techniques: {', '.join(tech_strs)}."
        )

    def get_tactic_context(self, mapping: ATTACKMapping) -> str:
        """Generate tactical context for justifications."""
        if not mapping.techniques:
            return "No MITRE ATT&CK mapping available for this CVE."

        lines = []
        for t in mapping.techniques:
            lines.append(f"• {t['technique']} ({t['name']}) - {t['tactic']}")

        return (
            f"MITRE ATT&CK Analysis:\n"
            f"This vulnerability maps to {len(mapping.techniques)} technique(s) "
            f"across {len(set(mapping.tactics))} tactic(s):\n"
            + "\n".join(lines)
            + f"\n{mapping.kill_chain_summary}"
        )
