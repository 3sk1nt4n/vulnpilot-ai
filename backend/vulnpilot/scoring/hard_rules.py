"""
VulnPilot AI - Hard Rules Engine (Lock 1)
YAML-based rules that fire BEFORE AI scoring.
AI CANNOT override these. Period.

Key rule: KEV = CRITICAL, always. No exceptions.
"""

import logging
from dataclasses import dataclass
from typing import Optional

import yaml

from vulnpilot.scoring.vprs import VPRSResult
from vulnpilot.scanners.base import NormalizedVuln
from vulnpilot.threatintel.base import ThreatIntelResult

logger = logging.getLogger(__name__)


@dataclass
class HardRuleMatch:
    """Result when a hard rule fires."""
    rule_name: str
    description: str
    override_severity: Optional[str] = None
    minimum_vprs: Optional[float] = None
    maximum_vprs: Optional[float] = None
    maximum_severity: Optional[str] = None
    escalate: bool = False
    escalate_to: str = ""
    sla_hours: Optional[int] = None


class HardRulesEngine:
    """Lock 1 - Rules that AI cannot override."""

    def __init__(self, rules_path: str = "./config/hard_rules.yaml"):
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str) -> list[dict]:
        try:
            with open(path, "r") as f:
                config = yaml.safe_load(f)
                rules = config.get("rules", [])
                # Sort by priority (lower = higher priority)
                rules.sort(key=lambda r: r.get("priority", 999))
                logger.info(f"Loaded {len(rules)} hard rules from {path}")
                return rules
        except FileNotFoundError:
            logger.warning(f"Hard rules file not found at {path}")
            return []

    def _evaluate_condition(
        self, condition: dict, vuln: NormalizedVuln, intel: ThreatIntelResult
    ) -> bool:
        """Evaluate a single condition against vulnerability + intel data."""
        field_name = condition["field"]
        operator = condition["operator"]
        expected = condition["value"]

        # Build a lookup of all available fields
        field_map = {
            "in_kev": intel.in_kev,
            "epss_score": intel.epss_score,
            "ransomware_associated": intel.ransomware_associated,
            "exploit_for_sale": intel.exploit_for_sale,
            "exploit_available": intel.exploit_available,
            "active_scanning": intel.active_scanning,
            "dark_web_mentions": intel.dark_web_mentions,
            "is_internet_facing": vuln.is_internet_facing,
            "asset_tier": vuln.asset_tier,
            "has_waf": vuln.has_waf,
            "has_ips": vuln.has_ips,
            "is_segmented": vuln.is_segmented,
            "cvss_base_score": vuln.cvss_base_score,
        }

        actual = field_map.get(field_name)
        if actual is None:
            logger.warning(f"Hard rule field '{field_name}' not found in data")
            return False

        if operator == "equals":
            return actual == expected
        elif operator == "greater_than":
            return actual > expected
        elif operator == "less_than":
            return actual < expected
        elif operator == "greater_equal":
            return actual >= expected
        elif operator == "less_equal":
            return actual <= expected
        elif operator == "not_equals":
            return actual != expected
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False

    def evaluate(
        self, vuln: NormalizedVuln, intel: ThreatIntelResult, vprs_result: VPRSResult
    ) -> tuple[VPRSResult, Optional[HardRuleMatch]]:
        """Apply hard rules to a VPRS result. Rules fire in priority order.

        Args:
            vuln: Normalized vulnerability data
            intel: Threat intelligence enrichment
            vprs_result: The calculated VPRS score (may be overridden)

        Returns:
            Tuple of (possibly modified VPRSResult, HardRuleMatch if triggered)
        """
        for rule in self.rules:
            matched = False

            # Single condition
            if "condition" in rule:
                matched = self._evaluate_condition(rule["condition"], vuln, intel)

            # Multiple conditions with AND/OR logic
            elif "conditions" in rule:
                logic = rule.get("logic", "and").lower()
                results = [
                    self._evaluate_condition(c, vuln, intel)
                    for c in rule["conditions"]
                ]
                if logic == "and":
                    matched = all(results)
                elif logic == "or":
                    matched = any(results)

            if matched:
                action = rule.get("action", {})
                match = HardRuleMatch(
                    rule_name=rule["name"],
                    description=rule.get("description", ""),
                    override_severity=action.get("override_severity"),
                    minimum_vprs=action.get("minimum_vprs"),
                    maximum_vprs=action.get("maximum_vprs"),
                    maximum_severity=action.get("maximum_severity"),
                    escalate=action.get("escalate", False),
                    escalate_to=action.get("escalate_to", ""),
                    sla_hours=action.get("sla_hours"),
                )

                # Apply overrides
                if match.override_severity:
                    vprs_result.severity = match.override_severity
                if match.minimum_vprs and vprs_result.vprs_score < match.minimum_vprs:
                    vprs_result.vprs_score = match.minimum_vprs
                if match.maximum_vprs and vprs_result.vprs_score > match.maximum_vprs:
                    vprs_result.vprs_score = match.maximum_vprs
                if match.sla_hours:
                    vprs_result.sla_hours = match.sla_hours

                vprs_result.hard_rule_triggered = True
                vprs_result.hard_rule_name = match.rule_name
                vprs_result.hard_rule_details = match.description

                logger.info(
                    f"Hard rule '{match.rule_name}' triggered for {vuln.cve_id}: "
                    f"severity={match.override_severity}, min_vprs={match.minimum_vprs}"
                )

                # First matching rule wins (priority order)
                return vprs_result, match

        return vprs_result, None
