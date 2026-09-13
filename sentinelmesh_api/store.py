from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Device, Event


class JsonlStore:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.devices_path = root / "devices.jsonl"
        self.events_path = root / "events.jsonl"

    def _read(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def devices(self) -> list[Device]:
        return [Device(**row) for row in self._read(self.devices_path)]

    def events(self, limit: int = 100) -> list[Event]:
        rows = self._read(self.events_path)[-limit:]
        return [Event(**row) for row in reversed(rows)]

    def replace_devices(self, devices: list[Device]) -> None:
        payload = "".join(json.dumps(item.to_dict(), sort_keys=True) + "\n" for item in devices)
        self.devices_path.write_text(payload, encoding="utf-8")

    def append_event(self, event: Event) -> None:
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
