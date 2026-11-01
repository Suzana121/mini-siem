"""Describe the machine a benchmark ran on, so numbers are never quoted without it.

    python -m benchmarks.machine     # print the JSON header
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], timeout: float = 5) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _cpu_model() -> str | None:
    if sys.platform == "darwin":
        return _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith(("model name", "hardware", "processor\t: arm")):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def _ram_bytes() -> int | None:
    if sys.platform == "darwin":
        value = _run(["sysctl", "-n", "hw.memsize"])
        return int(value) if value else None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return None


def _physical_cores() -> int | None:
    if sys.platform == "darwin":
        value = _run(["sysctl", "-n", "hw.physicalcpu"])
        return int(value) if value else None
    return None


def git_info() -> dict:
    commit = _run(["git", "rev-parse", "HEAD"])
    status = _run(["git", "status", "--porcelain", "--", ".", ":!benchmarks/results", ":!benchmarks/RESULTS.md"])
    return {"commit": commit, "dirty": bool(status) if status is not None else None}


def docker_info() -> dict | None:
    """Docker engine limits (what the compose stack gets). None when docker is unavailable."""
    if not shutil.which("docker"):
        return None
    raw = _run(["docker", "info", "--format", "{{json .}}"], timeout=10)
    if not raw:
        return None
    try:
        info = json.loads(raw)
    except ValueError:
        return None
    keys = ("ServerVersion", "NCPU", "MemTotal", "OperatingSystem", "OSType", "Architecture", "Driver")
    return {k: info.get(k) for k in keys}


def collect(include_docker: bool = False) -> dict:
    import pydantic

    git = git_info()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": git["commit"],
        "dirty_tree": git["dirty"],
        "cpu_model": _cpu_model(),
        "cpu_logical_cores": os.cpu_count(),
        "cpu_physical_cores": _physical_cores(),
        "ram_bytes": _ram_bytes(),
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "pydantic": pydantic.VERSION,
        "docker": docker_info() if include_docker else None,
    }


if __name__ == "__main__":
    print(json.dumps(collect(include_docker=True), indent=2))
