"""Process collector module for Mini EDR Linux Agent.

Scans Linux processes using psutil, extracting execution metadata:
PID, PPID, process name, username, executable path, CPU %, Memory %,
RSS bytes, and start time.

Handles NoSuchProcess, AccessDenied, and ZombieProcess exceptions gracefully
so that individual process permissions or short-lived processes never crash the agent.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

import psutil

logger = logging.getLogger(__name__)

# Standard attributes requested from psutil.process_iter for performance
PROCESS_ATTRS = (
    "pid",
    "ppid",
    "name",
    "username",
    "exe",
    "cpu_percent",
    "memory_percent",
    "memory_info",
    "create_time",
)


def _format_start_time(create_time: Optional[float]) -> Optional[str]:
    """Convert epoch timestamp to ISO 8601 UTC string."""
    if create_time is None or create_time <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(create_time, timezone.utc)
        return dt.isoformat()
    except (ValueError, OSError, OverflowError) as exc:
        logger.debug("Failed to format create_time %s: %s", create_time, exc)
        return None


def _clean_process_name(name: Optional[str], exe_path: Optional[str], pid: int) -> str:
    """Ensure process_name is non-empty, stripped, and safely bounded."""
    if name and name.strip():
        return name.strip()[:255]
    if exe_path and exe_path.strip():
        # Use filename of executable
        parts = exe_path.strip().rsplit("/", 1)
        base = parts[-1] if len(parts) > 1 else parts[0]
        if base.strip():
            return base.strip()[:255]
    return f"proc-{pid}"


def _sanitize_numeric(val: Any, min_val: Optional[float] = None, max_val: Optional[float] = None) -> Optional[float]:
    """Validate and clamp numeric metric value."""
    if val is None or isinstance(val, bool):
        return None
    try:
        num = float(val)
        if min_val is not None:
            num = max(min_val, num)
        if max_val is not None:
            num = min(max_val, num)
        return round(num, 2)
    except (ValueError, TypeError, OverflowError):
        return None


def collect_single_process(proc: psutil.Process) -> Optional[Dict[str, Any]]:
    """Extract and validate metadata for a single process instance."""
    try:
        # Use proc.info if pre-populated by process_iter, or call as_dict
        info = proc.info if hasattr(proc, "info") and proc.info else proc.as_dict(attrs=list(PROCESS_ATTRS))

        pid = info.get("pid")
        if pid is None or pid < 0:
            return None

        ppid = info.get("ppid")
        if ppid is not None and ppid < 0:
            ppid = None

        exe_path = info.get("exe")
        if exe_path and not isinstance(exe_path, str):
            exe_path = str(exe_path)

        process_name = _clean_process_name(info.get("name"), exe_path, pid)

        username = info.get("username")
        if username and not isinstance(username, str):
            username = str(username)

        cpu_percent = _sanitize_numeric(info.get("cpu_percent"), min_val=0.0)
        memory_percent = _sanitize_numeric(info.get("memory_percent"), min_val=0.0, max_val=100.0)

        rss_bytes: Optional[int] = None
        mem_info = info.get("memory_info")
        if mem_info is not None and hasattr(mem_info, "rss"):
            try:
                rss_val = int(mem_info.rss)
                if rss_val >= 0:
                    rss_bytes = rss_val
            except (ValueError, TypeError):
                rss_bytes = None

        create_time = info.get("create_time")
        process_started_at = _format_start_time(create_time)

        return {
            "pid": pid,
            "ppid": ppid,
            "process_name": process_name,
            "username": username,
            "exe_path": exe_path,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "rss_bytes": rss_bytes,
            "process_started_at": process_started_at,
        }

    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        # Process ended before or during inspection
        return None
    except psutil.AccessDenied:
        # Permission denied to full process info; fallback to PID/Name if possible
        try:
            return {
                "pid": proc.pid,
                "ppid": None,
                "process_name": f"proc-{proc.pid}",
                "username": None,
                "exe_path": None,
                "cpu_percent": None,
                "memory_percent": None,
                "rss_bytes": None,
                "process_started_at": None,
            }
        except Exception:
            return None
    except Exception as exc:
        logger.debug("Unexpected error collecting process PID %s: %s", getattr(proc, "pid", "?"), exc)
        return None


def collect_processes(sort_by: str = "pid") -> List[Dict[str, Any]]:
    """Scan and return all accessible processes currently running on the system.

    Parameters:
        sort_by: Attribute to sort results by ('pid', 'cpu_percent', 'memory_percent').
    """
    results: List[Dict[str, Any]] = []

    for proc in psutil.process_iter(attrs=list(PROCESS_ATTRS)):
        data = collect_single_process(proc)
        if data is not None:
            results.append(data)

    if sort_by == "pid":
        results.sort(key=lambda p: p["pid"])
    elif sort_by in ("cpu_percent", "memory_percent"):
        results.sort(key=lambda p: p.get(sort_by) or 0.0, reverse=True)

    # Enrich each process with parent_name resolved from the snapshot PID map
    pid_to_name = {p["pid"]: p["process_name"] for p in results if "pid" in p and "process_name" in p}
    for p in results:
        ppid = p.get("ppid")
        p["parent_name"] = pid_to_name.get(ppid) if ppid is not None else None

    return results


def get_process_by_pid(pid: int) -> Optional[Dict[str, Any]]:
    """Retrieve metadata for a specific PID on demand."""
    try:
        proc = psutil.Process(pid)
        return collect_single_process(proc)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None
    except psutil.AccessDenied:
        return {
            "pid": pid,
            "ppid": None,
            "process_name": f"proc-{pid}",
            "username": None,
            "exe_path": None,
            "cpu_percent": None,
            "memory_percent": None,
            "rss_bytes": None,
            "process_started_at": None,
        }
    except Exception as exc:
        logger.debug("Error looking up process PID %s: %s", pid, exc)
        return None


def collect_process_snapshot(
    agent_id: str,
    message_id: Optional[str] = None,
    schema_version: str = "1.0",
) -> Dict[str, Any]:
    """Collect full process snapshot formatted according to Data Contract envelope."""
    now_utc = datetime.now(timezone.utc).isoformat()
    processes = collect_processes(sort_by="pid")

    return {
        "schema_version": schema_version,
        "message_id": message_id or str(uuid.uuid4()),
        "agent_id": agent_id,
        "collected_at": now_utc,
        "payload": {
            "process_count": len(processes),
            "processes": processes,
        },
    }


class ProcessCollector:
    """Process collector instance managing process sampling and snapshot serialization."""

    def __init__(self, agent_id: str, schema_version: str = "1.0"):
        self.agent_id = agent_id
        self.schema_version = schema_version

    def collect_processes(self, sort_by: str = "pid") -> List[Dict[str, Any]]:
        return collect_processes(sort_by=sort_by)

    def get_process(self, pid: int) -> Optional[Dict[str, Any]]:
        return get_process_by_pid(pid)

    def collect_snapshot(self, message_id: Optional[str] = None) -> Dict[str, Any]:
        return collect_process_snapshot(
            agent_id=self.agent_id,
            message_id=message_id,
            schema_version=self.schema_version,
        )
