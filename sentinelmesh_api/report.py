from __future__ import annotations

import json
import csv
import io
from typing import Any


def render_report(snapshot: dict[str, Any], json_output: bool = False) -> str:
    if json_output:
        return json.dumps(snapshot, ensure_ascii=True, indent=2) + "\n"

    summary = snapshot["summary"]
    analysis = snapshot.get("analysis", {})
    lines = [
        "SENTINELMESH NETWORK INVENTORY",
        "=" * 34,
        f"Generated: {snapshot['generated_at']}",
        f"Visible devices: {summary['total']}",
        f"New devices: {summary['new']}",
        f"Elevated risk: {summary['elevated_risk']}",
        f"Inventory quality: {analysis.get('inventory_quality', 'n/a')}",
        f"Networks: {', '.join(analysis.get('networks', {}).keys()) or 'n/a'}",
        "",
        "DEVICES",
        "-------",
    ]
    for device in snapshot["devices"]:
        reasons = ", ".join(device["risk_reasons"]) or "no elevated indicators"
        lines.append(
            f"{device['device_id']} | {device['address']} | "
            f"{device['status']} | risk={device['risk']} | {reasons}"
        )
    return "\n".join(lines) + "\n"


def render_csv(snapshot: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["device_id", "address", "hostname", "source", "status", "risk", "risk_reasons"])
    writer.writeheader()
    for device in snapshot.get("devices", []):
        writer.writerow({
            "device_id": device.get("device_id", ""),
            "address": device.get("address", ""),
            "hostname": device.get("hostname", "") or "",
            "source": device.get("source", ""),
            "status": device.get("status", ""),
            "risk": device.get("risk", 0),
            "risk_reasons": ";".join(device.get("risk_reasons", [])),
        })
    return output.getvalue()


def render_diff(diff: dict[str, Any]) -> str:
    lines = ["SENTINELMESH BASELINE DIFF", "=" * 27]
    for label in ("added", "removed"):
        lines.append(f"{label.upper()}: {len(diff.get(label, []))}")
        lines.extend(f"  {item.get('device_id')} | {item.get('address')}" for item in diff.get(label, []))
    lines.append(f"CHANGED: {len(diff.get('changed', []))}")
    for item in diff.get("changed", []):
        before = item["before"]
        after = item["after"]
        lines.append(f"  {before.get('device_id')} | {before.get('address')} -> {after.get('address')}")
    return "\n".join(lines) + "\n"