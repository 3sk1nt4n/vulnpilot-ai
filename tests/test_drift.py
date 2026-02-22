"""
VulnPilot AI - Drift Detector Tests
Tests snapshot_scores, check_drift, get_drift_log, clear_drift_log, run_simulated_drift.
"""

import sys
import os
import json
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from unittest.mock import patch


@pytest.fixture(autouse=True)
def drift_tmp_paths(tmp_path):
    """Redirect drift store/log to temp files for all tests."""
    store_path = str(tmp_path / "drift_store.json")
    log_path = str(tmp_path / "drift_log.json")
    with patch.dict(os.environ, {
        "DRIFT_STORE_PATH": store_path,
        "DRIFT_LOG_PATH": log_path,
    }):
        # Reload module to pick up new paths
        import importlib
        import vulnpilot.drift as drift_mod
        importlib.reload(drift_mod)
        yield drift_mod


def _make_results(*cves):
    results = []
    for cve_id, vprs, epss, in_kev, dw in cves:
        results.append({
            "cve_id": cve_id, "vprs_score": vprs, "severity": "high",
            "epss_score": epss, "in_kev": in_kev, "dark_web_mentions": dw,
            "is_internet_facing": True, "asset_tier": "tier_1",
        })
    return results


class TestSnapshotScores:
    def test_basic_snapshot(self, drift_tmp_paths):
        drift = drift_tmp_paths
        results = _make_results(
            ("CVE-2024-1111", 85.0, 0.9, True, 5),
            ("CVE-2024-2222", 40.0, 0.2, False, 0),
        )
        r = drift.snapshot_scores(results)
        assert r["ok"] is True
        assert r["cves_stored"] == 2

    def test_empty_results(self, drift_tmp_paths):
        r = drift_tmp_paths.snapshot_scores([])
        assert r["ok"] is True
        assert r["cves_stored"] == 0

    def test_skips_no_cve_id(self, drift_tmp_paths):
        """Empty cve_id entries are skipped during storage but len(results) is returned."""
        r = drift_tmp_paths.snapshot_scores([{"vprs_score": 50}])
        # The function returns len(results) not len(stored), so 1 input = 1 reported
        assert r["cves_stored"] == 1
        assert r["ok"] is True


class TestCheckDrift:
    def test_no_previous_snapshot(self, drift_tmp_paths):
        drift = drift_tmp_paths
        results = _make_results(("CVE-2024-1111", 85.0, 0.9, True, 5))
        r = drift.check_drift(results)
        assert r["ok"] is True
        assert r["drifts_found"] == 0

    def test_detects_score_increase(self, drift_tmp_paths):
        drift = drift_tmp_paths
        # Snapshot initial
        old = _make_results(("CVE-2024-1111", 40.0, 0.2, False, 0))
        drift.snapshot_scores(old)
        # New results with big increase
        new = _make_results(("CVE-2024-1111", 95.0, 0.9, True, 5))
        r = drift.check_drift(new)
        assert r["drifts_found"] == 1
        assert r["drifts"][0]["direction"] == "UP"
        assert r["drifts"][0]["diff"] == 55.0

    def test_detects_score_decrease(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = _make_results(("CVE-2024-1111", 90.0, 0.9, True, 5))
        drift.snapshot_scores(old)
        new = _make_results(("CVE-2024-1111", 40.0, 0.2, False, 0))
        r = drift.check_drift(new)
        assert r["drifts_found"] == 1
        assert r["drifts"][0]["direction"] == "DOWN"

    def test_no_drift_under_threshold(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = _make_results(("CVE-2024-1111", 50.0, 0.5, False, 0))
        drift.snapshot_scores(old)
        new = _make_results(("CVE-2024-1111", 55.0, 0.5, False, 0))
        r = drift.check_drift(new)
        assert r["drifts_found"] == 0

    def test_drift_reasons_epss(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = _make_results(("CVE-2024-1111", 40.0, 0.1, False, 0))
        drift.snapshot_scores(old)
        new = _make_results(("CVE-2024-1111", 80.0, 0.9, False, 0))
        r = drift.check_drift(new)
        reasons = r["drifts"][0]["reasons"]
        assert any("EPSS" in reason for reason in reasons)

    def test_drift_reasons_kev_added(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = _make_results(("CVE-2024-1111", 40.0, 0.5, False, 0))
        drift.snapshot_scores(old)
        new = _make_results(("CVE-2024-1111", 100.0, 0.5, True, 0))
        r = drift.check_drift(new)
        reasons = r["drifts"][0]["reasons"]
        assert any("KEV" in reason for reason in reasons)

    def test_drift_reasons_dark_web(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = _make_results(("CVE-2024-1111", 40.0, 0.5, False, 0))
        drift.snapshot_scores(old)
        new = _make_results(("CVE-2024-1111", 80.0, 0.5, False, 10))
        r = drift.check_drift(new)
        reasons = r["drifts"][0]["reasons"]
        assert any("Dark web" in reason for reason in reasons)

    def test_drift_reasons_hard_rule(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = [{"cve_id": "CVE-2024-1111", "vprs_score": 40.0, "severity": "medium",
                "epss_score": 0.5, "in_kev": False, "dark_web_mentions": 0, "hard_rule": ""}]
        drift.snapshot_scores(old)
        new = [{"cve_id": "CVE-2024-1111", "vprs_score": 100.0, "severity": "critical",
                "epss_score": 0.5, "in_kev": False, "dark_web_mentions": 0,
                "hard_rule": "kev_always_critical"}]
        r = drift.check_drift(new)
        reasons = r["drifts"][0]["reasons"]
        assert any("Hard rule" in reason for reason in reasons)

    def test_custom_threshold(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = _make_results(("CVE-2024-1111", 50.0, 0.5, False, 0))
        drift.snapshot_scores(old)
        new = _make_results(("CVE-2024-1111", 55.0, 0.5, False, 0))
        r = drift.check_drift(new, threshold=5)
        assert r["drifts_found"] == 1


class TestDriftLog:
    def test_get_drift_log_empty(self, drift_tmp_paths):
        log = drift_tmp_paths.get_drift_log()
        assert log["events"] == []
        assert log["stats"]["total_checks"] == 0

    def test_clear_drift_log(self, drift_tmp_paths):
        drift = drift_tmp_paths
        old = _make_results(("CVE-2024-1111", 40.0, 0.1, False, 0))
        drift.snapshot_scores(old)
        new = _make_results(("CVE-2024-1111", 95.0, 0.9, True, 5))
        drift.check_drift(new)
        # Should have events
        log = drift.get_drift_log()
        assert log["stats"]["total_drifts"] > 0
        # Clear
        drift.clear_drift_log()
        log = drift.get_drift_log()
        assert log["events"] == []
        assert log["stats"]["total_drifts"] == 0


class TestSimulatedDrift:
    def test_run_simulated_drift(self, drift_tmp_paths):
        r = drift_tmp_paths.run_simulated_drift()
        assert r["ok"] is True
        assert r["mode"] == "simulated"
        assert r["scenarios_injected"] == 4
        assert len(r["events"]) == 4

    def test_simulated_events_have_required_fields(self, drift_tmp_paths):
        r = drift_tmp_paths.run_simulated_drift()
        for event in r["events"]:
            assert "cve_id" in event
            assert "old_vprs" in event
            assert "new_vprs" in event
            assert "direction" in event
            assert "reasons" in event
            assert event["simulated"] is True

    def test_simulated_drift_updates_log(self, drift_tmp_paths):
        drift = drift_tmp_paths
        drift.run_simulated_drift()
        log = drift.get_drift_log()
        assert log["stats"]["total_drifts"] == 4
        assert len(log["events"]) == 4


class TestDriftIOEdgeCases:
    def test_corrupt_store_file(self, drift_tmp_paths, tmp_path):
        drift = drift_tmp_paths
        # Write corrupt data to store
        store_path = os.environ["DRIFT_STORE_PATH"]
        with open(store_path, "w") as f:
            f.write("{corrupt json!!!}")
        # Should handle gracefully
        store = drift._load_store()
        assert "snapshots" in store

    def test_corrupt_log_file(self, drift_tmp_paths, tmp_path):
        drift = drift_tmp_paths
        log_path = os.environ["DRIFT_LOG_PATH"]
        with open(log_path, "w") as f:
            f.write("not valid json")
        log = drift._load_log()
        assert "events" in log
