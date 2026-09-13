from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "apps" / "api"))

from sentinelmesh_api.models import Device
from sentinelmesh_api.privacy import pseudonymize
from sentinelmesh_api.risk import score
from sentinelmesh_api.analysis import compare_snapshots, enrich_snapshot


def test_pseudonym_is_stable_and_does_not_expose_value():
    result = pseudonymize("192.168.1.4", "test-secret")
    assert result == pseudonymize("192.168.1.4", "test-secret")
    assert "192.168.1.4" not in result


def test_new_device_has_explainable_risk():
    device = Device("sm-test", "192.168.1.4", None, "arp", "2026-09-13T00:00:00+00:00", "2026-09-13T00:00:00+00:00", "new")
    value, reasons = score(device, datetime.now(timezone.utc))
    assert value >= 35
    assert "device_seen_for_the_first_time" in reasons
    assert "hostname_not_resolved" in reasons


def test_old_observation_is_stale():
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    device = Device("sm-test", "10.0.0.4", "lab-node", "local", old, old, "known")
    value, reasons = score(device)
    assert value >= 10
    assert "observation_is_stale" in reasons


def test_snapshot_comparison_ignores_expected_timestamps():
    device = {
        "device_id": "sm-test", "address": "10.0.0.4", "hostname": "lab",
        "source": "local", "first_seen": "a", "last_seen": "old",
        "status": "known", "risk": 0, "risk_reasons": [], "metadata": {},
    }
    newer = {**device, "last_seen": "new"}
    assert compare_snapshots({"devices": [device]}, {"devices": [newer]})["changed"] == []


def test_snapshot_analysis_groups_networks_and_scores_quality():
    snapshot = {"devices": [{"address": "10.0.0.4", "hostname": "lab", "source": "local", "risk": 0}]}
    analysis = enrich_snapshot(snapshot)["analysis"]
    assert analysis["networks"] == {"10.0.0.0/24": 1}
    assert analysis["inventory_quality"] == 100
