"""Database Maintenance and Telemetry Retention Pruning for Mini EDR Linux.

Implements TTL pruning of aged historical telemetry to maintain a bounded SQLite
footprint and prevent unbounded database disk growth over time (FINDING-PHASE02-03).
"""

import logging
from typing import Any, Dict, Optional

from server.repositories.event_repository import EventRepository
from server.repositories.metrics_repository import MetricsRepository
from server.repositories.process_repository import ProcessRepository

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 7


def prune_telemetry(
    database_path: Optional[str] = None,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> Dict[str, Any]:
    """Prune historical telemetry older than retention_days.

    Deletes expired system_metrics, process_snapshots (with cascaded process_observations),
    and aged security_events.

    Args:
        database_path: Optional path to SQLite database.
        retention_days: Number of days of telemetry to retain (must be > 0).

    Returns:
        Dictionary containing counts of deleted records.
    """
    if not isinstance(retention_days, int) or retention_days <= 0:
        raise ValueError("retention_days must be an integer greater than 0")

    metrics_repo = MetricsRepository(database_path)
    proc_repo = ProcessRepository(database_path)
    event_repo = EventRepository(database_path)

    deleted_metrics = metrics_repo.prune_older_than(days=retention_days)
    deleted_snapshots = proc_repo.prune_older_than(days=retention_days)
    # Security events retain a 30-day window or max(retention_days, 30) for compliance
    deleted_events = event_repo.prune_older_than(days=max(retention_days, 30))

    logger.info(
        "Pruned telemetry older than %d days: %d metrics, %d snapshots, %d events",
        retention_days,
        deleted_metrics,
        deleted_snapshots,
        deleted_events,
    )

    return {
        "success": True,
        "retention_days": retention_days,
        "deleted_metrics": deleted_metrics,
        "deleted_snapshots": deleted_snapshots,
        "deleted_events": deleted_events,
    }
