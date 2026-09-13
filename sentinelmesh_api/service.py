from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

from .collector import collect
from .models import Device, Event, utc_now
from .privacy import pseudonymize
from .risk import score
from .store import JsonlStore
from .analysis import enrich_snapshot


class SentinelService:
    def __init__(self, data_dir: Path, identity_secret: str = "local-development-secret"):
        self.store = JsonlStore(data_dir)
        self.identity_secret = identity_secret

    def refresh(self) -> list[Device]:
        previous = {device.device_id: device for device in self.store.devices()}
        current: list[Device] = []
        now = utc_now()
        for observation in collect():
            identity = observation.metadata.get("mac", observation.address)
            device_id = pseudonymize(identity, self.identity_secret)
            old = previous.get(device_id)
            device = Device(
                device_id=device_id,
                address=observation.address,
                hostname=observation.hostname,
                source=observation.source,
                first_seen=old.first_seen if old else now,
                last_seen=now,
                status="known" if old else "new",
                metadata=observation.metadata,
            )
            device.risk, device.risk_reasons = score(device)
            current.append(device)
            if not old:
                self.store.append_event(Event(str(uuid.uuid4()), "device_first_seen", now, device_id, "New device observed", "notice"))
            elif old.metadata != device.metadata:
                self.store.append_event(Event(str(uuid.uuid4()), "device_changed", now, device_id, "Device metadata changed", "warning"))
        self.store.replace_devices(current)
        return current

    def snapshot(self) -> dict:
        devices = self.store.devices()
        return enrich_snapshot({
            "service": "SentinelMesh",
            "version": "0.1.0",
            "generated_at": utc_now(),
            "devices": [device.to_dict() for device in devices],
            "events": [event.to_dict() for event in self.store.events()],
            "summary": {
                "total": len(devices),
                "new": sum(item.status == "new" for item in devices),
                "elevated_risk": sum(item.risk >= 40 for item in devices),
            },
        })
