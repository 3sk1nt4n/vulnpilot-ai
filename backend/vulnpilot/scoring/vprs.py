"""
VulnPilot AI - VPRS Scoring Engine
The heart of the product. Pure Python + NumPy. Zero external dependencies.

VPRS Score (0-100) = Σ(factor_score × weight)

6 Factors:
  EPSS (25%) + KEV (20%) + Dark Web (15%) +
  Asset Criticality (20%) + Reachability (12%) + Controls (8%)

THIS CODE IS IDENTICAL IN BOTH LOCAL AND CLOUD MODES.
Only the justification text quality changes (Ollama vs Claude).
The actual risk ranking, priority order, and ticket routing are the same.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import yaml

from vulnpilot.scanners.base import NormalizedVuln
from vulnpilot.threatintel.base import ThreatIntelResult

logger = logging.getLogger(__name__)


@dataclass
class VPRSResult:
    """Complete VPRS scoring output."""

    cve_id: str
    vprs_score: float             # Final score 0-100
    severity: str                 # critical, high, medium, low, info

    # --- 6 Factor Breakdown ---
    epss_raw: float = 0.0        # Raw EPSS (0-1)
    epss_component: float = 0.0  # Weighted contribution to VPRS
    kev_match: bool = False
    kev_component: float = 0.0
    dark_web_score: float = 0.0
    dark_web_component: float = 0.0
    asset_score: float = 0.0
    asset_component: float = 0.0
    reachability_score: float = 0.0
    reachability_component: float = 0.0
    controls_score: float = 0.0
    controls_component: float = 0.0

    # --- Hard Rules (Lock 1) ---
    hard_rule_triggered: bool = False
    hard_rule_name: str = ""
    hard_rule_details: str = ""

    # --- Weights Used (for audit trail) ---
    weights_used: dict = field(default_factory=dict)

    # --- SLA ---
    sla_hours: int = 0
    priority: str = "P4"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "vprs_score": self.vprs_score,
            "severity": self.severity,
            "components": {
                "epss": {"raw": self.epss_raw, "weighted": self.epss_component},
                "kev": {"match": self.kev_match, "weighted": self.kev_component},
                "dark_web": {"score": self.dark_web_score, "weighted": self.dark_web_component},
                "asset": {"score": self.asset_score, "weighted": self.asset_component},
                "reachability": {"score": self.reachability_score, "weighted": self.reachability_component},
                "controls": {"score": self.controls_score, "weighted": self.controls_component},
            },
            "hard_rule_triggered": self.hard_rule_triggered,
            "hard_rule_name": self.hard_rule_name,
            "weights_used": self.weights_used,
            "sla_hours": self.sla_hours,
            "priority": self.priority,
        }


class VPRSEngine:
    """VPRS Scoring Engine - the math behind VulnPilot AI."""

    def __init__(self, weights_path: str = "./config/vprs_weights.yaml"):
        self.config = self._load_config(weights_path)
        self.weights = self.config["weights"]
        self.thresholds = self.config["thresholds"]
        self.factor_scoring = self.config.get("factor_scoring", {})
        self._validate_weights()

    def _load_config(self, path: str) -> dict:
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"VPRS weights file not found at {path}, using defaults")
            return {
                "weights": {
                    "epss": 0.25, "kev": 0.20, "dark_web": 0.15,
                    "asset_criticality": 0.20, "reachability": 0.12, "controls": 0.08,
                },
                "thresholds": {"critical": 85, "high": 65, "medium": 40, "low": 15},
                "factor_scoring": {},
            }

    def _validate_weights(self):
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"VPRS weights must sum to 1.0, got {total}. "
                f"Weights: {self.weights}"
            )

    def score_epss(self, epss_score: float) -> float:
        """Score EPSS factor (0-100).
        Uses nonlinear thresholds from config.
        """
        thresholds = self.factor_scoring.get("epss", {}).get("thresholds", [])
        if thresholds:
            for t in thresholds:
                if epss_score >= t["min"]:
                    return t["score"]
        # Fallback: linear scaling
        return min(100, epss_score * 100)

    def score_kev(self, in_kev: bool, ransomware: bool = False) -> float:
        """Score KEV factor (0-100). Binary: in KEV = 100, not = 0."""
        kev_config = self.factor_scoring.get("kev", {})
        base = kev_config.get("in_kev", 100) if in_kev else kev_config.get("not_in_kev", 0)
        if ransomware and in_kev:
            base = min(100, base + kev_config.get("ransomware_bonus", 10))
        return base

    def score_dark_web(self, intel: ThreatIntelResult) -> float:
        """Score dark web factor (0-100)."""
        dw_config = self.factor_scoring.get("dark_web", {})

        if intel.exploit_for_sale:
            return dw_config.get("exploit_for_sale", 100)
        if intel.ransomware_associated:
            return dw_config.get("ransomware_associated", 90)
        if intel.exploit_available:
            return dw_config.get("exploit_available", 80)
        if intel.active_scanning:
            return dw_config.get("active_scanning", 70)
        if intel.dark_web_mentions >= 5:
            return dw_config.get("mentions_high", 60)
        if intel.dark_web_mentions >= 1:
            return dw_config.get("mentions_low", 30)
        return dw_config.get("none", 0)

    def score_asset_criticality(self, vuln: NormalizedVuln) -> float:
        """Score asset criticality factor (0-100) based on tier."""
        ac_config = self.factor_scoring.get("asset_criticality", {})
        tier_map = {
            "tier_1": ac_config.get("tier_1", 100),
            "tier_2": ac_config.get("tier_2", 60),
            "tier_3": ac_config.get("tier_3", 25),
        }
        return tier_map.get(vuln.asset_tier, 25)

    def score_reachability(self, vuln: NormalizedVuln) -> float:
        """Score reachability factor (0-100)."""
        r_config = self.factor_scoring.get("reachability", {})
        if vuln.is_internet_facing:
            return r_config.get("internet_facing", 100)
        if vuln.is_segmented:
            return r_config.get("segmented", 15)
        return r_config.get("internal_reachable", 40)

    def score_controls(self, vuln: NormalizedVuln) -> float:
        """Score compensating controls factor (0-100).
        HIGHER = MORE exposed (less protection).
        """
        c_config = self.factor_scoring.get("controls", {})
        has_waf = vuln.has_waf
        has_ips = vuln.has_ips
        is_seg = vuln.is_segmented

        if has_waf and has_ips and is_seg:
            return c_config.get("waf_ips_segmented", 15)
        if has_waf and has_ips:
            return c_config.get("waf_and_ips", 40)
        if has_waf:
            return c_config.get("waf_only", 70)
        if has_ips:
            return c_config.get("ips_only", 70)
        if is_seg:
            return c_config.get("segmented_only", 60)
        return c_config.get("no_controls", 100)

    def calculate_vprs(
        self, vuln: NormalizedVuln, intel: ThreatIntelResult
    ) -> VPRSResult:
        """Calculate the full VPRS score for a vulnerability.

        This is THE core calculation. Identical in local and cloud modes.

        VPRS = (EPSS×0.25) + (KEV×0.20) + (DarkWeb×0.15) +
               (AssetCrit×0.20) + (Reach×0.12) + (Controls×0.08)
        """
        # Score each factor (0-100)
        epss_factor = self.score_epss(intel.epss_score)
        kev_factor = self.score_kev(intel.in_kev, intel.ransomware_associated)
        dw_factor = self.score_dark_web(intel)
        asset_factor = self.score_asset_criticality(vuln)
        reach_factor = self.score_reachability(vuln)
        ctrl_factor = self.score_controls(vuln)

        # Apply weights
        epss_weighted = epss_factor * self.weights["epss"]
        kev_weighted = kev_factor * self.weights["kev"]
        dw_weighted = dw_factor * self.weights["dark_web"]
        asset_weighted = asset_factor * self.weights["asset_criticality"]
        reach_weighted = reach_factor * self.weights["reachability"]
        ctrl_weighted = ctrl_factor * self.weights["controls"]

        # Sum to VPRS (0-100)
        vprs_score = round(
            epss_weighted + kev_weighted + dw_weighted +
            asset_weighted + reach_weighted + ctrl_weighted,
            1
        )

        # Clamp to 0-100
        vprs_score = max(0.0, min(100.0, vprs_score))

        # Determine severity
        severity = self._score_to_severity(vprs_score)

        # Map severity to SLA
        sla_map = {
            "critical": (24, "P1"),
            "high": (72, "P2"),
            "medium": (336, "P3"),
            "low": (720, "P4"),
            "info": (0, "P5"),
        }
        sla_hours, priority = sla_map.get(severity, (720, "P4"))

        return VPRSResult(
            cve_id=vuln.cve_id,
            vprs_score=vprs_score,
            severity=severity,
            epss_raw=intel.epss_score,
            epss_component=round(epss_weighted, 2),
            kev_match=intel.in_kev,
            kev_component=round(kev_weighted, 2),
            dark_web_score=dw_factor,
            dark_web_component=round(dw_weighted, 2),
            asset_score=asset_factor,
            asset_component=round(asset_weighted, 2),
            reachability_score=reach_factor,
            reachability_component=round(reach_weighted, 2),
            controls_score=ctrl_factor,
            controls_component=round(ctrl_weighted, 2),
            weights_used=dict(self.weights),
            sla_hours=sla_hours,
            priority=priority,
        )

    def _score_to_severity(self, score: float) -> str:
        if score >= self.thresholds["critical"]:
            return "critical"
        if score >= self.thresholds["high"]:
            return "high"
        if score >= self.thresholds["medium"]:
            return "medium"
        if score >= self.thresholds["low"]:
            return "low"
        return "info"
