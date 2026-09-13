from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Iterable


class NativeModuleUnavailable(RuntimeError):
    pass


def module_path(root: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return root / name / f"{name}{suffix}"


def run_process(command: list[str], payload: str = "", cwd: Path | None = None) -> str:
    result = subprocess.run(command, input=payload, text=True, capture_output=True, timeout=10, check=False, cwd=cwd)
    if result.returncode != 0:
        raise RuntimeError(f"native module failed ({command[0]}): {result.stderr.strip()}")
    return result.stdout


def run_jsonl(executable: Path, rows: Iterable[dict[str, Any]], args: list[str] | None = None) -> list[dict[str, Any]]:
    if not executable.exists():
        raise NativeModuleUnavailable(f"native module is not built: {executable}")
    payload = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)
    output_text = run_process([str(executable), *(args or [])], payload)
    output: list[dict[str, Any]] = []
    for line in output_text.splitlines():
        if line.strip():
            output.append(json.loads(line))
    return output