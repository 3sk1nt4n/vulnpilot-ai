"""
VulnPilot Drift Detector (Lock 3)
Real drift detection + simulated demo mode.

Stores previous VPRS snapshots, re-checks threat intel,
compares scores, flags drifts with full audit trail.
"""

import json
import os
import time
import random
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("vulnpilot.drift")

# In-memory drift store (persisted to JSON file)
DRIFT_STORE_PATH = os.environ.get("DRIFT_STORE_PATH", "/tmp/vulnpilot_drift_store.json")
DRIFT_LOG_PATH = os.environ.get("DRIFT_LOG_PATH", "/tmp/vulnpilot_drift_log.json")

# Default interval: 6h for all tiers (configurable)
DEFAULT_INTERVAL_HOURS = 6


def _load_store():
    """Load previous score snapshots."""
    if os.path.exists(DRIFT_STORE_PATH):
        try:
            with open(DRIFT_STORE_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"snapshots": {}, "last_check": {}, "config": {
        "tier_1_hours": int(os.environ.get("DRIFT_TIER1_HOURS", 1)),
        "tier_2_hours": int(os.environ.get("DRIFT_TIER2_HOURS", 3)),
        "tier_3_hours": int(os.environ.get("DRIFT_TIER3_HOURS", DEFAULT_INTERVAL_HOURS)),
        "default_hours": DEFAULT_INTERVAL_HOURS,
    }}


def _save_store(store):
    try:
        with open(DRIFT_STORE_PATH, "w") as f:
            json.dump(store, f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Could not save drift store: {e}")


def _load_log():
    if os.path.exists(DRIFT_LOG_PATH):
        try:
            with open(DRIFT_LOG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"events": [], "stats": {"total_checks": 0, "total_drifts": 0, "last_check": None}}


def _save_log(log):
    try:
        with open(DRIFT_LOG_PATH, "w") as f:
            json.dump(log, f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Could not save drift log: {e}")


def snapshot_scores(results):
    """Take a snapshot of current VPRS scores for drift comparison."""
    store = _load_store()
    now = datetime.utcnow().isoformat()
    
    for v in results:
        cve_id = v.get("cve_id", "")
        if not cve_id:
            continue
        store["snapshots"][cve_id] = {
            "vprs_score": v.get("vprs_score", 0),
            "severity": v.get("severity", ""),
            "epss_score": v.get("epss_score", 0),
            "in_kev": v.get("in_kev", False),
            "dark_web_mentions": v.get("dark_web_mentions", 0),
            "is_internet_facing": v.get("is_internet_facing", False),
            "asset_tier": v.get("asset_tier", "standard"),
            "hard_rule": v.get("hard_rule", ""),
            "snapshot_time": now,
            "components": v.get("components", {}),
        }
    
    store["last_check"]["snapshot"] = now
    _save_store(store)
    logger.info(f"Drift snapshot saved: {len(results)} CVEs")
    return {"ok": True, "cves_stored": len(results)}


def check_drift(results, threshold=10):
    """
    Compare current results against stored snapshots.
    Returns drift events for any CVE whose VPRS changed by >= threshold.
    """
    store = _load_store()
    log = _load_log()
    now = datetime.utcnow().isoformat()
    drifts = []
    checked = 0
    
    for v in results:
        cve_id = v.get("cve_id", "")
        if not cve_id or cve_id not in store.get("snapshots", {}):
            continue
        
        checked += 1
        prev = store["snapshots"][cve_id]
        old_vprs = prev.get("vprs_score", 0)
        new_vprs = v.get("vprs_score", 0)
        diff = new_vprs - old_vprs
        
        if abs(diff) >= threshold:
            # Build reason trail
            reasons = []
            old_epss = prev.get("epss_score", 0)
            new_epss = v.get("epss_score", 0)
            if abs(new_epss - old_epss) > 0.01:
                reasons.append(f"EPSS changed: {old_epss*100:.2f}% → {new_epss*100:.2f}%")
            
            old_kev = prev.get("in_kev", False)
            new_kev = v.get("in_kev", False)
            if new_kev and not old_kev:
                reasons.append("ADDED to CISA KEV - now confirmed exploited")
            
            old_dw = prev.get("dark_web_mentions", 0)
            new_dw = v.get("dark_web_mentions", 0)
            if new_dw != old_dw:
                reasons.append(f"Dark web IoCs: {old_dw} → {new_dw}")
            
            old_sev = prev.get("severity", "")
            new_sev = v.get("severity", "")
            
            old_rule = prev.get("hard_rule", "")
            new_rule = v.get("hard_rule", "")
            if new_rule != old_rule:
                reasons.append(f"Hard rule changed: '{old_rule}' → '{new_rule}'")
            
            drift_event = {
                "cve_id": cve_id,
                "old_vprs": old_vprs,
                "new_vprs": new_vprs,
                "diff": round(diff, 1),
                "direction": "UP" if diff > 0 else "DOWN",
                "old_severity": old_sev,
                "new_severity": new_sev,
                "reasons": reasons,
                "detected_at": now,
                "tier": v.get("asset_tier", "standard"),
                "hostname": v.get("hostname", "unknown"),
            }
            drifts.append(drift_event)
            log["events"].insert(0, drift_event)  # newest first
    
    # Keep log trimmed to last 100 events
    log["events"] = log["events"][:100]
    log["stats"]["total_checks"] += 1
    log["stats"]["total_drifts"] += len(drifts)
    log["stats"]["last_check"] = now
    log["stats"]["cves_checked"] = checked
    
    _save_log(log)
    
    # Update snapshots with new scores
    snapshot_scores(results)
    
    return {
        "ok": True,
        "checked": checked,
        "drifts_found": len(drifts),
        "drifts": drifts,
        "timestamp": now,
    }


def get_drift_log():
    """Get the drift event log."""
    return _load_log()


def clear_drift_log():
    """Clear drift history."""
    log = {"events": [], "stats": {"total_checks": 0, "total_drifts": 0, "last_check": None}}
    _save_log(log)
    store = _load_store()
    store["snapshots"] = {}
    _save_store(store)
    return {"ok": True}


# ═══════════════════════════════════════════════════════
# SIMULATED DRIFT DEMO
# Injects realistic drift scenarios for demo purposes
# ═══════════════════════════════════════════════════════

DRIFT_SCENARIOS = [
    {
        "id": "kev_addition",
        "title": "🚨 CISA KEV Addition - Score Explosion",
        "description": "CISA just added CVE-2024-38178 to the Known Exploited Vulnerabilities catalog 47 minutes ago.",
        "cve_id": "CVE-2024-38178",
        "old_state": {
            "vprs_score": 42.0, "severity": "MEDIUM", "epss_score": 0.28,
            "in_kev": False, "dark_web_mentions": 2, "hard_rule": "",
            "components": {"epss": 8.5, "kev": 0, "dark_web": 3, "asset": 16, "reachability": 8.5, "controls": 6}
        },
        "new_state": {
            "vprs_score": 100.0, "severity": "CRITICAL", "epss_score": 0.28,
            "in_kev": True, "dark_web_mentions": 2, "hard_rule": "kev_always_critical",
            "components": {"epss": 8.5, "kev": 20, "dark_web": 3, "asset": 16, "reachability": 8.5, "controls": 6}
        },
        "reasons": [
            "ADDED to CISA KEV - now confirmed exploited",
            "Hard rule changed: '' → 'kev_always_critical'",
        ],
        "time_ago_minutes": 47,
    },
    {
        "id": "epss_spike",
        "title": "📈 EPSS Spike - PoC Published on GitHub",
        "description": "A proof-of-concept exploit for CVE-2024-9474 was published on GitHub 2 hours ago. EPSS jumped from 22% to 78%.",
        "cve_id": "CVE-2024-9474",
        "old_state": {
            "vprs_score": 35.0, "severity": "MEDIUM", "epss_score": 0.22,
            "in_kev": False, "dark_web_mentions": 0, "hard_rule": "",
            "components": {"epss": 6.5, "kev": 0, "dark_web": 0, "asset": 12, "reachability": 10, "controls": 6.5}
        },
        "new_state": {
            "vprs_score": 78.0, "severity": "HIGH", "epss_score": 0.78,
            "in_kev": False, "dark_web_mentions": 3, "hard_rule": "high_epss_internet_facing",
            "components": {"epss": 23.5, "kev": 0, "dark_web": 4.5, "asset": 12, "reachability": 10, "controls": 6.5}
        },
        "reasons": [
            "EPSS changed: 22.00% → 78.00%",
            "Dark web IoCs: 0 → 3",
            "Hard rule changed: '' → 'high_epss_internet_facing'",
        ],
        "time_ago_minutes": 118,
    },
    {
        "id": "darkweb_surge",
        "title": "🕸️ Dark Web Surge - Exploit Kit Integration",
        "description": "CVE-2024-5921 exploit was integrated into a major exploit kit. Dark web mentions surged from 0 to 14 IoCs.",
        "cve_id": "CVE-2024-5921",
        "old_state": {
            "vprs_score": 28.0, "severity": "LOW", "epss_score": 0.08,
            "in_kev": False, "dark_web_mentions": 0, "hard_rule": "no_signals_floor",
            "components": {"epss": 2.4, "kev": 0, "dark_web": 0, "asset": 12, "reachability": 6, "controls": 7.6}
        },
        "new_state": {
            "vprs_score": 72.0, "severity": "HIGH", "epss_score": 0.35,
            "in_kev": False, "dark_web_mentions": 14, "hard_rule": "",
            "components": {"epss": 10.5, "kev": 0, "dark_web": 15, "asset": 12, "reachability": 10, "controls": 7.6}
        },
        "reasons": [
            "EPSS changed: 8.00% → 35.00%",
            "Dark web IoCs: 0 → 14",
            "Hard rule changed: 'no_signals_floor' → ''",
        ],
        "time_ago_minutes": 195,
    },
    {
        "id": "score_decrease",
        "title": "📉 Risk Reduced - Patch Deployed + Controls Active",
        "description": "CVE-2024-0012 was patched on 3 of 4 affected hosts. Compensating controls now active. Risk decreased.",
        "cve_id": "CVE-2024-0012",
        "old_state": {
            "vprs_score": 70.0, "severity": "HIGH", "epss_score": 0.55,
            "in_kev": False, "dark_web_mentions": 3, "hard_rule": "",
            "components": {"epss": 16.5, "kev": 0, "dark_web": 4.5, "asset": 16, "reachability": 12, "controls": 3}
        },
        "new_state": {
            "vprs_score": 38.0, "severity": "MEDIUM", "epss_score": 0.55,
            "in_kev": False, "dark_web_mentions": 3, "hard_rule": "",
            "components": {"epss": 16.5, "kev": 0, "dark_web": 4.5, "asset": 8, "reachability": 4, "controls": 8}
        },
        "reasons": [
            "Asset criticality reduced after patching (16 → 8)",
            "Reachability decreased (12 → 4) - no longer internet-facing",
            "Controls score improved (3 → 8) - WAF + EDR active",
        ],
        "time_ago_minutes": 310,
    },
]


def run_simulated_drift():
    """
    Run a simulated drift demo with realistic scenarios.
    Injects fake timeline events showing how drift detection catches changes.
    """
    log = _load_log()
    now = datetime.utcnow()
    events = []
    
    for scenario in DRIFT_SCENARIOS:
        event_time = now - timedelta(minutes=scenario["time_ago_minutes"])
        event = {
            "cve_id": scenario["cve_id"],
            "old_vprs": scenario["old_state"]["vprs_score"],
            "new_vprs": scenario["new_state"]["vprs_score"],
            "diff": round(scenario["new_state"]["vprs_score"] - scenario["old_state"]["vprs_score"], 1),
            "direction": "UP" if scenario["new_state"]["vprs_score"] > scenario["old_state"]["vprs_score"] else "DOWN",
            "old_severity": scenario["old_state"]["severity"],
            "new_severity": scenario["new_state"]["severity"],
            "reasons": scenario["reasons"],
            "detected_at": event_time.isoformat(),
            "scenario_title": scenario["title"],
            "scenario_description": scenario["description"],
            "tier": "tier_1" if scenario["new_state"]["vprs_score"] >= 80 else "tier_2",
            "hostname": "demo-host",
            "simulated": True,
        }
        events.append(event)
    
    # Sort by time (newest first)
    events.sort(key=lambda e: e["detected_at"], reverse=True)
    
    # Add to log
    log["events"] = events + log["events"]
    log["events"] = log["events"][:100]
    log["stats"]["total_checks"] += 4
    log["stats"]["total_drifts"] += len(events)
    log["stats"]["last_check"] = now.isoformat()
    
    _save_log(log)
    
    return {
        "ok": True,
        "mode": "simulated",
        "scenarios_injected": len(events),
        "events": events,
        "message": "Drift demo scenarios injected. These simulate realistic threat intel changes detected over the past 5 hours.",
    }
