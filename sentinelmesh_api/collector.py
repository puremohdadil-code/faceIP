from __future__ import annotations

import json
import ipaddress
import platform
import re
import socket
import subprocess
from dataclasses import dataclass


@dataclass
class Observation:
    address: str
    hostname: str | None
    source: str
    metadata: dict[str, str]


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


def _arp_rows() -> list[Observation]:
    output = _run(["arp", "-a"])
    rows: list[Observation] = []
    for line in output.splitlines():
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{11,17})", line)
        if match:
            address = ipaddress.ip_address(match.group(1))
            if address.is_multicast or address.is_unspecified or address.is_reserved:
                continue
            if match.group(2).lower() in {"ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"}:
                continue
            rows.append(Observation(str(address), None, "arp", {"mac": match.group(2).lower()}))
    return rows


def _local_row() -> Observation:
    host = socket.gethostname()
    address = socket.gethostbyname(host)
    return Observation(address, host, "local", {"platform": platform.platform()})


def collect() -> list[Observation]:
    """Collect local metadata and the OS neighbor table; never captures payloads."""
    rows = [_local_row(), *_arp_rows()]
    unique: dict[str, Observation] = {}
    for row in rows:
        unique[row.address] = row
    return list(unique.values())


def observation_json(rows: list[Observation]) -> str:
    return json.dumps([row.__dict__ for row in rows], sort_keys=True)
