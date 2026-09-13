from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Any, Iterable


def _device_map(devices: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(device["device_id"]): device for device in devices}


def _comparison_view(device: dict[str, Any]) -> dict[str, Any]:
    ignored = {"first_seen", "last_seen"}
    return {key: value for key, value in device.items() if key not in ignored}


def compare_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    old = _device_map(before.get("devices", []))
    new = _device_map(after.get("devices", []))
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    changed: list[dict[str, Any]] = []
    for key in sorted(old.keys() & new.keys()):
        if _comparison_view(old[key]) != _comparison_view(new[key]):
            changed.append({"before": old[key], "after": new[key]})
    return {"added": added, "removed": removed, "changed": changed}


def _network(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address)
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return "invalid"


def enrich_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    devices = snapshot.get("devices", [])
    networks = Counter(_network(device.get("address", "")) for device in devices)
    missing_names = sum(not device.get("hostname") for device in devices)
    high_risk = sum(int(device.get("risk", 0)) >= 40 for device in devices)
    total = len(devices)
    quality = 100 if not total else round(100 - (missing_names / total * 40) - (high_risk / total * 60))
    result = dict(snapshot)
    result["analysis"] = {
        "networks": dict(sorted(networks.items())),
        "missing_hostname_count": missing_names,
        "high_risk_count": high_risk,
        "inventory_quality": max(0, min(100, quality)),
        "source_counts": dict(Counter(device.get("source", "unknown") for device in devices)),
    }
    return result