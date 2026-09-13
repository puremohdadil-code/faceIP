from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def save(path: Path, snapshot: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"baseline does not exist: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("devices", []), list):
        raise ValueError("baseline must contain a snapshot object with a devices list")
    return value