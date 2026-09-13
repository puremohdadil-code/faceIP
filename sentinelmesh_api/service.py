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
from .native import NativeModuleUnavailable, run_jsonl, run_process


class SentinelService:
    def __init__(self, data_dir: Path, identity_secret: str = "local-development-secret", native_root: Path | None = None):
        self.store = JsonlStore(data_dir)
        self.identity_secret = identity_secret
        self.native_root = native_root
        self.module_status: dict[str, str] = {}

    def _native(self, name: str) -> Path | None:
        if not self.native_root:
            return None
        suffix = ".exe" if __import__("os").name == "nt" else ""
        path = self.native_root / name / f"{name}{suffix}"
        return path if path.exists() else None

    def _scheduler_allows(self, count: int) -> bool:
        if not self.native_root:
            self.module_status["java_scheduler"] = "disabled"
            return True
        class_dir = self.native_root / "java"
        if not class_dir.exists():
            self.module_status["java_scheduler"] = "unavailable"
            return True
        try:
            result = run_process([
                "java", "-cp", str(class_dir),
                "com.sentinelmesh.scheduler.SchedulePolicy",
            ], f"{count}\n")
            allowed = result.strip() == "ALLOW"
            self.module_status["java_scheduler"] = "active" if allowed else "denied"
            return allowed
        except (OSError, RuntimeError):
            self.module_status["java_scheduler"] = "unavailable"
            return True

    def _lua_assessment(self, device: Device) -> tuple[int, list[str]]:
        if not self.native_root:
            self.module_status["lua_policy"] = "disabled"
            return 0, []
        script = self.native_root.parent.parent / "modules" / "lua_policy" / "main.lua"
        if not script.exists():
            self.module_status["lua_policy"] = "unavailable"
            return 0, []
        payload = f"{device.status}\t{device.hostname or ''}\t{device.source}\n"
        try:
            result = run_process(["lua", "main.lua"], payload, cwd=script.parent)
            score_text, reasons_text = result.strip().split("\t", 1)
            self.module_status["lua_policy"] = "active"
            return int(score_text), [item for item in reasons_text.split(",") if item]
        except (OSError, RuntimeError, ValueError):
            self.module_status["lua_policy"] = "unavailable"
            return 0, []

    def _asm_checksum(self, device: Device) -> str | None:
        if not self.native_root:
            self.module_status["asm_checksum"] = "disabled"
            return None
        executable = self._native("asm_checksum")
        if not executable:
            self.module_status["asm_checksum"] = "unavailable"
            return None
        try:
            import json
            result = run_process([str(executable)], json.dumps(device.to_dict(), sort_keys=True))
            self.module_status["asm_checksum"] = "active"
            return result.strip()
        except (OSError, RuntimeError):
            self.module_status["asm_checksum"] = "unavailable"
            return None

    def _normalize(self, observations: list[dict]) -> list[dict]:
        executable = self._native("cpp_identity")
        if not executable:
            return observations
        try:
            return [message["payload"] for message in run_jsonl(executable, observations)]
        except (NativeModuleUnavailable, RuntimeError, ValueError):
            return observations

    def refresh(self) -> list[Device]:
        previous = {device.device_id: device for device in self.store.devices()}
        current: list[Device] = []
        now = utc_now()
        c_executable = self._native("c_neighbor")
        collected = collect(c_executable)
        if not self._scheduler_allows(len(collected)):
            raise RuntimeError("java scheduler denied this collection size")
        self.module_status["c_neighbor"] = "active" if c_executable else "fallback"
        observations = [item.__dict__ for item in collected]
        observations = self._normalize(observations)
        self.module_status["cpp_identity"] = "active" if self._native("cpp_identity") else "fallback"
        for observation in observations:
            address = observation.get("address", "")
            hostname = observation.get("hostname") or None
            source = observation.get("source", "unknown")
            metadata = {key: value for key, value in observation.items() if key not in {"address", "hostname", "source"}}
            identity = metadata.get("mac", address)
            device_id = pseudonymize(identity, self.identity_secret)
            old = previous.get(device_id)
            device = Device(
                device_id=device_id,
                address=address,
                hostname=hostname,
                source=source,
                first_seen=old.first_seen if old else now,
                last_seen=now,
                status="known" if old else "new",
                metadata=metadata,
            )
            policy_score, policy_reasons = self._lua_assessment(device)
            checksum = self._asm_checksum(device)
            if checksum:
                device.metadata["record_checksum"] = checksum
            risk_executable = self._native("rust_risk")
            if risk_executable:
                try:
                    rust_input = device.to_dict()
                    rust_input["lua_score"] = policy_score
                    rust_input["lua_reasons"] = ",".join(policy_reasons)
                    assessment = run_jsonl(risk_executable, [rust_input])[0]["payload"]
                    device.risk = int(assessment.get("risk", 0))
                    device.risk_reasons = [assessment.get("reason", "")]
                except (NativeModuleUnavailable, RuntimeError, ValueError, IndexError, KeyError):
                    device.risk, device.risk_reasons = score(device)
            else:
                device.risk, device.risk_reasons = score(device)
                device.risk = max(device.risk, policy_score)
                device.risk_reasons = list(dict.fromkeys(device.risk_reasons + policy_reasons))
            self.module_status["rust_risk"] = "active" if risk_executable else "fallback"
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
            "pipeline": {"modules": dict(self.module_status)},
        })
