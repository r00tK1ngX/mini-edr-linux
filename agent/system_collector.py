"""System metrics and host information collector for Mini EDR Linux Agent.

Collects host identity (hostname, IP address, OS) and system performance
metrics (CPU %, RAM %, Disk %, Uptime) using standard Linux interfaces and psutil.
Handles exceptions gracefully to prevent agent crashes.
"""

from datetime import datetime, timezone
import logging
from pathlib import Path
import platform
import socket
import time
from typing import Any, Dict, Optional
import uuid

import psutil

logger = logging.getLogger(__name__)


def get_hostname() -> str:
    """Retrieve system hostname safely."""
    try:
        name = socket.gethostname()
        if name and name.strip():
            return name.strip()
    except Exception as exc:
        logger.debug("socket.gethostname failed: %s", exc)

    try:
        node = platform.node()
        if node and node.strip():
            return node.strip()
    except Exception as exc:
        logger.debug("platform.node failed: %s", exc)

    try:
        etc_hostname = Path("/etc/hostname")
        if etc_hostname.is_file():
            content = etc_hostname.read_text(encoding="utf-8").strip()
            if content:
                return content
    except Exception as exc:
        logger.debug("Reading /etc/hostname failed: %s", exc)

    return "unknown-host"


def get_ip_address() -> Optional[str]:
    """Retrieve primary non-loopback IPv4/IPv6 address.

    Returns None if no network interface is configured or reachable.
    """
    # Strategy 1: Open a UDP socket towards a public DNS server.
    # No packets are actually sent over the wire, but the kernel routing
    # table selects the primary outbound interface.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.connect(("8.8.8.8", 80))
            candidate = sock.getsockname()[0]
            if candidate and not candidate.startswith("127."):
                return candidate
    except Exception as exc:
        logger.debug("Outbound UDP probe for IP failed: %s", exc)

    # Strategy 2: Inspect interfaces via psutil.
    try:
        addrs = psutil.net_if_addrs()
        for iface_name, addr_list in addrs.items():
            # Skip loopback interfaces
            if iface_name.lower().startswith("lo"):
                continue
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if ip and not ip.startswith("127."):
                        return ip
    except Exception as exc:
        logger.debug("psutil.net_if_addrs inspection failed: %s", exc)

    # Strategy 3: Resolve hostname
    try:
        resolved = socket.gethostbyname(get_hostname())
        if resolved and not resolved.startswith("127."):
            return resolved
    except Exception as exc:
        logger.debug("socket.gethostbyname failed: %s", exc)

    return None


def get_os_info() -> str:
    """Retrieve clean operating system name and version."""
    # Method 1: freedesktop_os_release (Python 3.10+ standard on Linux)
    try:
        os_release = platform.freedesktop_os_release()
        pretty = os_release.get("PRETTY_NAME")
        if pretty and pretty.strip():
            return pretty.strip()
        name = os_release.get("NAME")
        version = os_release.get("VERSION") or os_release.get("VERSION_ID", "")
        if name:
            return f"{name} {version}".strip()
    except Exception as exc:
        logger.debug("platform.freedesktop_os_release failed: %s", exc)

    # Method 2: Manual parse of /etc/os-release
    try:
        os_release_path = Path("/etc/os-release")
        if os_release_path.is_file():
            data: Dict[str, str] = {}
            for line in os_release_path.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"').strip("'")
            if "PRETTY_NAME" in data:
                return data["PRETTY_NAME"]
            if "NAME" in data:
                return f"{data['NAME']} {data.get('VERSION_ID', '')}".strip()
    except Exception as exc:
        logger.debug("Parsing /etc/os-release failed: %s", exc)

    # Method 3: Platform fallback
    try:
        sys_name = platform.system()
        release = platform.release()
        return f"{sys_name} {release}".strip() or "Linux"
    except Exception:
        return "Linux"


def get_cpu_percent(interval: Optional[float] = 0.1) -> float:
    """Calculate CPU usage percentage within [0.0, 100.0]."""
    try:
        val = psutil.cpu_percent(interval=interval)
        if isinstance(val, (int, float)):
            return max(0.0, min(100.0, round(float(val), 2)))
    except Exception as exc:
        logger.warning("Failed to collect CPU usage: %s", exc)
    return 0.0


def get_memory_percent() -> float:
    """Calculate RAM memory usage percentage within [0.0, 100.0]."""
    try:
        val = psutil.virtual_memory().percent
        if isinstance(val, (int, float)):
            return max(0.0, min(100.0, round(float(val), 2)))
    except Exception as exc:
        logger.warning("Failed to collect Memory usage: %s", exc)
    return 0.0


def get_disk_percent(path: str = "/") -> float:
    """Calculate disk usage percentage for mount point within [0.0, 100.0]."""
    try:
        val = psutil.disk_usage(path).percent
        if isinstance(val, (int, float)):
            return max(0.0, min(100.0, round(float(val), 2)))
    except (PermissionError, FileNotFoundError, OSError) as exc:
        logger.debug("Disk usage for %s failed (%s), trying root fallback", path, exc)
        if path != "/":
            try:
                val = psutil.disk_usage("/").percent
                return max(0.0, min(100.0, round(float(val), 2)))
            except Exception:
                pass
    except Exception as exc:
        logger.warning("Failed to collect Disk usage for %s: %s", path, exc)
    return 0.0


def get_uptime_seconds() -> float:
    """Calculate system uptime in seconds (>= 0.0)."""
    # Method 1: psutil boot_time
    try:
        boot_time = psutil.boot_time()
        if boot_time > 0:
            uptime = time.time() - boot_time
            if uptime >= 0:
                return round(float(uptime), 1)
    except Exception as exc:
        logger.debug("psutil.boot_time calculation failed: %s", exc)

    # Method 2: read /proc/uptime directly
    try:
        uptime_file = Path("/proc/uptime")
        if uptime_file.is_file():
            parts = uptime_file.read_text(encoding="utf-8").split()
            if parts:
                val = float(parts[0])
                if val >= 0:
                    return round(val, 1)
    except Exception as exc:
        logger.debug("Reading /proc/uptime failed: %s", exc)

    return 0.0


def collect_metrics(
    disk_path: str = "/",
    cpu_interval: Optional[float] = 0.1,
) -> Dict[str, float]:
    """Collect current system performance metrics dictionary."""
    return {
        "cpu_percent": get_cpu_percent(interval=cpu_interval),
        "memory_percent": get_memory_percent(),
        "disk_percent": get_disk_percent(path=disk_path),
        "uptime_seconds": get_uptime_seconds(),
    }


def collect_system_info(
    agent_id: str,
    agent_version: str = "1.0.0",
    disk_path: str = "/",
    cpu_interval: Optional[float] = 0.1,
) -> Dict[str, Any]:
    """Collect complete endpoint identity and metric snapshot (heartbeat format)."""
    return {
        "agent_id": agent_id,
        "hostname": get_hostname(),
        "ip_address": get_ip_address(),
        "os": get_os_info(),
        "agent_version": agent_version,
        "metrics": collect_metrics(disk_path=disk_path, cpu_interval=cpu_interval),
    }


class SystemCollector:
    """System collector instance with configurable parameters."""

    def __init__(
        self,
        agent_id: str,
        agent_version: str = "1.0.0",
        disk_path: str = "/",
        cpu_interval: Optional[float] = 0.1,
    ):
        self.agent_id = agent_id
        self.agent_version = agent_version
        self.disk_path = disk_path
        self.cpu_interval = cpu_interval

    def get_hostname(self) -> str:
        return get_hostname()

    def get_ip_address(self) -> Optional[str]:
        return get_ip_address()

    def get_os_info(self) -> str:
        return get_os_info()

    def get_cpu_percent(self) -> float:
        return get_cpu_percent(interval=self.cpu_interval)

    def get_memory_percent(self) -> float:
        return get_memory_percent()

    def get_disk_percent(self) -> float:
        return get_disk_percent(path=self.disk_path)

    def get_uptime_seconds(self) -> float:
        return get_uptime_seconds()

    def collect_metrics(self) -> Dict[str, float]:
        return collect_metrics(
            disk_path=self.disk_path,
            cpu_interval=self.cpu_interval,
        )

    def collect_system_info(self) -> Dict[str, Any]:
        return collect_system_info(
            agent_id=self.agent_id,
            agent_version=self.agent_version,
            disk_path=self.disk_path,
            cpu_interval=self.cpu_interval,
        )

    def collect_telemetry_envelope(self) -> Dict[str, Any]:
        """Wrap system metrics in standard Phase 2 Message Envelope."""
        return {
            "schema_version": "1.0",
            "message_id": str(uuid.uuid4()),
            "agent_id": self.agent_id,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "payload": self.collect_metrics(),
        }
