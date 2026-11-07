"""File Integrity Monitoring (FIM) module for Mini EDR Linux Agent.

Monitors configured directories and sensitive files (e.g., /etc, /bin, /tmp).
Calculates SHA-256 cryptographic checksums, detects file creation, modification,
and deletion (transitioning state to 'missing'), and generates structured events
compliant with the EDR Data Contract.
"""

from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import stat
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

logger = logging.getLogger(__name__)

# Default buffer size for reading and hashing files (64 KiB)
HASH_CHUNK_SIZE = 64 * 1024

# Default maximum file size to hash (50 MiB) to avoid high memory/CPU pressure
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024

# Empty file SHA-256 constant (64 lowercase hex characters)
EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _utc_now() -> str:
    """Return current UTC time in ISO 8601 string format."""
    return datetime.now(timezone.utc).isoformat()


def compute_sha256(file_path: str, max_size: int = DEFAULT_MAX_FILE_SIZE) -> Optional[str]:
    """Calculate the SHA-256 hexadecimal hash of a regular file.

    Returns:
        Lowercase 64-character hexadecimal SHA-256 string, or None if reading fails,
        file is a symlink, or file exceeds max_size.
    """
    try:
        # Check lstat to avoid reading through symlinks
        st = os.lstat(file_path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return None

        file_size = st.st_size
        if file_size > max_size:
            logger.warning("File %s exceeds max hash size (%d bytes), skipping", file_path, file_size)
            return None

        if file_size == 0:
            return EMPTY_FILE_SHA256

        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    except (PermissionError, FileNotFoundError, IsADirectoryError, OSError) as exc:
        logger.debug("Failed to compute SHA-256 for %s: %s", file_path, exc)
        return None


def inspect_file(
    file_path: str,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    previous_record: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Inspect a single regular file and extract FIM metadata.

    Returns:
        Dictionary containing path, sha256, size, mtime_ns, file_mode, and state='present'.
        Returns None if file is not a regular file, is a symlink, or cannot be read.
    """
    try:
        # Check lstat first to reject symlinks and prevent traversal / TOCTOU
        st = os.lstat(file_path)
        if stat.S_ISLNK(st.st_mode):
            logger.debug("Skipping symlink %s to avoid traversal/TOCTOU", file_path)
            return None

        # Only monitor regular files (skip sockets, fifos, character/block devices)
        if not stat.S_ISREG(st.st_mode):
            return None

        resolved_path = str(Path(file_path).resolve())
        # Ensure resolved path is still a regular file
        st_res = os.stat(resolved_path, follow_symlinks=False)
        if not stat.S_ISREG(st_res.st_mode):
            return None

        file_mode = st_res.st_mode & 0o7777
        mtime_ns = int(getattr(st_res, "st_mtime_ns", int(st_res.st_mtime * 1e9)))
        file_size = st_res.st_size

        # Quick check optimization: If size, mtime, and mode haven't changed, reuse cached sha256
        if (
            previous_record
            and previous_record.get("sha256")
            and previous_record.get("mtime_ns") == mtime_ns
            and previous_record.get("file_size_bytes") == file_size
            and previous_record.get("file_mode") == file_mode
        ):
            sha256_hash = previous_record["sha256"]
        else:
            sha256_hash = compute_sha256(resolved_path, max_size=max_size)
            if sha256_hash is None:
                return None

        now = _utc_now()
        first_seen = previous_record.get("first_seen_at", now) if previous_record else now

        return {
            "file_path": resolved_path,
            "sha256": sha256_hash,
            "file_size_bytes": file_size,
            "mtime_ns": mtime_ns,
            "file_mode": file_mode,
            "state": "present",
            "first_seen_at": first_seen,
            "last_seen_at": now,
            "last_checked_at": now,
        }

    except (PermissionError, FileNotFoundError, OSError) as exc:
        logger.debug("Failed to inspect file %s: %s", file_path, exc)
        return None


def scan_monitored_paths(
    monitored_paths: List[str],
    recursive: bool = True,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    previous_baseline: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Scan all configured files and directories.

    Returns:
        Mapping of {normalized_file_path: file_record}.
    """
    results: Dict[str, Dict[str, Any]] = {}
    prev_map = previous_baseline or {}

    for target in monitored_paths:
        try:
            target_path = Path(target).resolve()
            if not target_path.exists():
                logger.debug("Monitored target does not exist: %s", target)
                continue

            # Skip symlink targets
            if target_path.is_symlink():
                logger.debug("Skipping symlink target %s", target)
                continue

            if target_path.is_file():
                resolved_key = str(target_path)
                record = inspect_file(
                    resolved_key,
                    max_size=max_file_size,
                    previous_record=prev_map.get(resolved_key),
                )
                if record:
                    results[record["file_path"]] = record
                continue

            if target_path.is_dir():
                for root, _, files in os.walk(str(target_path), followlinks=False):
                    for file_name in files:
                        full_path = os.path.join(root, file_name)
                        try:
                            # Reject symlinks inside scanned directory
                            if os.path.islink(full_path):
                                continue
                            resolved_key = str(Path(full_path).resolve())
                            record = inspect_file(
                                full_path,
                                max_size=max_file_size,
                                previous_record=prev_map.get(resolved_key),
                            )
                            if record:
                                results[record["file_path"]] = record
                        except (PermissionError, OSError):
                            continue
                    if not recursive:
                        break
        except (PermissionError, OSError) as exc:
            logger.warning("Error scanning path %s: %s", target, exc)

    return results


def detect_file_changes(
    previous_baseline: Dict[str, Dict[str, Any]],
    current_scan: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Compare the current scan against previous baseline to detect changes.

    Returns:
        Tuple of:
          - updated_baseline: New state dictionary containing present and missing files.
          - change_events: List of detected change events ('created', 'modified', 'deleted').
    """
    updated_baseline: Dict[str, Dict[str, Any]] = dict(previous_baseline)
    events: List[Dict[str, Any]] = []
    now = _utc_now()

    # 1. Detect Created and Modified files
    for file_path, current_record in current_scan.items():
        prev = updated_baseline.get(file_path)

        if prev is None:
            # File newly created
            updated_baseline[file_path] = current_record
            events.append({
                "change_type": "created",
                "file_path": file_path,
                "current": current_record,
                "previous": None,
                "detected_at": now,
            })
        elif prev.get("state") == "missing":
            # File was missing, now recreated
            updated_record = dict(current_record)
            updated_record["first_seen_at"] = prev.get("first_seen_at", current_record["first_seen_at"])
            updated_baseline[file_path] = updated_record
            events.append({
                "change_type": "created",
                "file_path": file_path,
                "current": updated_record,
                "previous": prev,
                "detected_at": now,
            })
        else:
            # Check for modifications: SHA-256 hash or permissions
            hash_changed = prev.get("sha256") != current_record["sha256"]
            mode_changed = prev.get("file_mode") != current_record["file_mode"]
            size_changed = prev.get("file_size_bytes") != current_record["file_size_bytes"]

            if hash_changed or mode_changed or size_changed:
                updated_record = dict(current_record)
                updated_record["first_seen_at"] = prev.get("first_seen_at", current_record["first_seen_at"])
                updated_baseline[file_path] = updated_record
                events.append({
                    "change_type": "modified",
                    "file_path": file_path,
                    "current": updated_record,
                    "previous": prev,
                    "detected_at": now,
                })
            else:
                # No change, refresh check timestamp
                updated_baseline[file_path]["last_checked_at"] = now

    # 2. Detect Deleted files
    for file_path, prev_record in list(updated_baseline.items()):
        if prev_record.get("state") == "present" and file_path not in current_scan:
            # File deleted: mark missing while preserving historical hash
            marked_missing = dict(prev_record)
            marked_missing["state"] = "missing"
            marked_missing["last_checked_at"] = now
            updated_baseline[file_path] = marked_missing

            events.append({
                "change_type": "deleted",
                "file_path": file_path,
                "current": marked_missing,
                "previous": prev_record,
                "detected_at": now,
            })

    return updated_baseline, events


def format_baseline_sync_payload(
    agent_id: str,
    baseline: Dict[str, Dict[str, Any]],
    message_id: Optional[str] = None,
    schema_version: str = "1.0",
) -> Dict[str, Any]:
    """Format full baseline state into Data Contract sync envelope (POST /api/v1/file-baselines)."""
    now = _utc_now()
    file_list = []
    for record in baseline.values():
        file_list.append({
            "file_path": record["file_path"],
            "sha256": record["sha256"],
            "file_size_bytes": record["file_size_bytes"],
            "mtime_ns": record["mtime_ns"],
            "file_mode": record["file_mode"],
            "state": record.get("state", "present"),
        })

    return {
        "schema_version": schema_version,
        "message_id": message_id or str(uuid.uuid4()),
        "agent_id": agent_id,
        "collected_at": now,
        "payload": {
            "files": file_list,
        },
    }


def format_fim_security_event(
    agent_id: str,
    change_event: Dict[str, Any],
    message_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert an individual FIM change event into a standard Security Event envelope."""
    change_type = change_event["change_type"]
    file_path = change_event["file_path"]
    curr = change_event.get("current") or {}
    prev = change_event.get("previous") or {}

    severity = "medium"
    if change_type == "deleted":
        severity = "high"
        title = f"Monitored file deleted: {file_path}"
    elif change_type == "created":
        severity = "medium"
        title = f"New file created in protected path: {file_path}"
    else:
        severity = "high"
        title = f"Monitored file integrity modified: {file_path}"

    evidence = {
        "file_path": file_path,
        "change_type": change_type,
        "current_sha256": curr.get("sha256"),
        "previous_sha256": prev.get("sha256"),
        "current_size": curr.get("file_size_bytes"),
        "previous_size": prev.get("file_size_bytes"),
        "current_mode": curr.get("file_mode"),
        "previous_mode": prev.get("file_mode"),
    }

    fingerprint = f"fim:{change_type}:{file_path}:{curr.get('sha256', '')}"

    detected_at = change_event.get("detected_at", _utc_now())

    return {
        "schema_version": "1.0",
        "message_id": message_id or str(uuid.uuid4()),
        "agent_id": agent_id,
        "collected_at": detected_at,
        "payload": {
            "event_type": f"fim_file_{change_type}",
            "severity": severity,
            "source": "agent",
            "title": title,
            "description": f"File {file_path} underwent {change_type} event",
            "occurred_at": detected_at,
            "fingerprint": fingerprint,
            "evidence": evidence,
        },
    }


class FileIntegrityMonitor:
    """File Integrity Monitor managing baseline state, path scanning, and diff events."""

    def __init__(
        self,
        agent_id: str,
        monitored_paths: Optional[List[str]] = None,
        recursive: bool = True,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ):
        self.agent_id = agent_id
        self.monitored_paths = monitored_paths or ["/etc", "/bin"]
        self.recursive = recursive
        self.max_file_size = max_file_size
        self.baseline: Dict[str, Dict[str, Any]] = {}

    def scan(self, previous_baseline: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
        """Perform a scan of all configured monitored paths."""
        return scan_monitored_paths(
            self.monitored_paths,
            recursive=self.recursive,
            max_file_size=self.max_file_size,
            previous_baseline=previous_baseline,
        )

    def initialize_baseline(self) -> int:
        """Scan and establish initial baseline without generating change events."""
        self.baseline = self.scan()
        return len(self.baseline)

    def scan_for_changes(self) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
        """Perform a scan and calculate changes without committing to internal baseline."""
        current_scan = self.scan(previous_baseline=self.baseline)
        return detect_file_changes(self.baseline, current_scan)

    def commit_baseline(self, new_baseline: Dict[str, Dict[str, Any]]) -> None:
        """Commit new baseline state after successful transmission."""
        self.baseline = new_baseline

    def check_for_changes(self) -> List[Dict[str, Any]]:
        """Perform a scan, update internal baseline, and return detected change events."""
        new_baseline, events = self.scan_for_changes()
        self.baseline = new_baseline
        return events

    def get_baseline_sync_payload(self, message_id: Optional[str] = None) -> Dict[str, Any]:
        """Produce the API sync envelope for the current baseline."""
        return format_baseline_sync_payload(
            agent_id=self.agent_id,
            baseline=self.baseline,
            message_id=message_id,
        )

    def get_security_events(self, changes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Transform change events into standard security event payloads."""
        return [format_fim_security_event(self.agent_id, change) for change in changes]
