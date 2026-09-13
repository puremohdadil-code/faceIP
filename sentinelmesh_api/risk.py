from __future__ import annotations

from datetime import datetime, timezone
from .models import Device


def score(device: Device, now: datetime | None = None) -> tuple[int, list[str]]:
    now = now or datetime.now(timezone.utc)
    reasons: list[str] = []
    total = 0
    if device.status == "new":
        total += 25
        reasons.append("device_seen_for_the_first_time")
    if not device.hostname:
        total += 10
        reasons.append("hostname_not_resolved")
    if device.source == "arp" and not device.metadata.get("mac"):
        total += 15
        reasons.append("incomplete_neighbor_identity")
    try:
        age = (now - datetime.fromisoformat(device.last_seen)).total_seconds()
        if age > 24 * 3600:
            total += 10
            reasons.append("observation_is_stale")
    except ValueError:
        total += 5
        reasons.append("invalid_observation_timestamp")
    return min(total, 100), reasons
