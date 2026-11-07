"""Agent Orchestrator module for Mini EDR Linux.

Coordinates collectors and the HTTP client into a unified operational loop:
- System collector (Heartbeat & System Telemetry)
- Process collector (Process Snapshots)
- File integrity monitor (Baseline initialization, change detection & security events)
- HTTP client (Bearer authentication, transmission, retries)

Handles SIGINT/SIGTERM gracefully, catches exceptions to ensure uninterrupted execution,
and supports both continuous daemon mode and single-cycle execution (--once).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import signal
import socket
import sys
import time
from typing import Any, Dict, List, Optional
import uuid

# Ensure project root is available in sys.path when executed directly as script
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv

from agent.client import (
    AgentAuthenticationError,
    AgentClient,
    AgentConnectionError,
    AgentRequestError,
)
from agent.file_integrity import FileIntegrityMonitor
from agent.process_collector import ProcessCollector
from agent.spool import EventSpool
from agent.system_collector import SystemCollector, get_hostname

logger = logging.getLogger("mini_edr_agent")


@dataclass
class AgentConfig:
    """Configuration container for the Mini EDR Agent."""

    agent_id: str
    server_url: str = "http://127.0.0.1:5000"
    api_token: str = ""
    agent_version: str = "1.0.0"
    heartbeat_interval: float = 5.0
    process_interval: float = 10.0
    fim_interval: float = 30.0
    monitored_paths: List[str] = field(default_factory=lambda: ["/etc", "/bin", "/tmp"])
    request_timeout: float = 5.0
    max_retries: int = 3
    spool_path: Optional[str] = None
    max_spool_size: int = 1000

    @classmethod
    def from_env(cls, env_path: Optional[str] = None) -> "AgentConfig":
        """Load configuration from environment variables or .env file."""
        if env_path:
            load_dotenv(dotenv_path=env_path)
        else:
            # Look for .env in project root
            root_env = Path(__file__).resolve().parent.parent / ".env"
            if root_env.is_file():
                load_dotenv(dotenv_path=root_env)
            else:
                load_dotenv()

        agent_id = (
            os.getenv("EDR_AGENT_ID")
            or get_hostname()
            or "lab-linux-01"
        ).strip()

        server_host = os.getenv("EDR_HOST", "127.0.0.1").strip()
        server_port = os.getenv("EDR_PORT", "5000").strip()
        default_url = f"http://{server_host}:{server_port}"
        server_url = os.getenv("EDR_SERVER_URL", default_url).strip()

        api_token = os.getenv("EDR_API_TOKEN", "").strip()
        agent_version = os.getenv("EDR_AGENT_VERSION", "1.0.0").strip()

        raw_paths = os.getenv("EDR_MONITORED_PATHS", "/etc,/bin,/tmp")
        monitored_paths = [p.strip() for p in raw_paths.split(",") if p.strip()]

        spool_path = os.getenv("EDR_SPOOL_PATH")
        if not spool_path:
            spool_path = str(Path(__file__).resolve().parent.parent / "data" / f"spool_{agent_id}.db")
        max_spool_size = int(os.getenv("EDR_MAX_SPOOL_SIZE", "1000"))

        return cls(
            agent_id=agent_id,
            server_url=server_url,
            api_token=api_token,
            agent_version=agent_version,
            heartbeat_interval=float(os.getenv("EDR_HEARTBEAT_INTERVAL", "5.0")),
            process_interval=float(os.getenv("EDR_PROCESS_SCAN_INTERVAL", "10.0")),
            fim_interval=float(os.getenv("EDR_FIM_SCAN_INTERVAL", "30.0")),
            monitored_paths=monitored_paths or ["/etc", "/bin", "/tmp"],
            request_timeout=float(os.getenv("EDR_REQUEST_TIMEOUT", "5.0")),
            max_retries=int(os.getenv("EDR_MAX_RETRIES", "3")),
            spool_path=spool_path,
            max_spool_size=max_spool_size,
        )


class AgentOrchestrator:
    """Coordinates collectors and transmits telemetry to the server."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        system_collector: Optional[SystemCollector] = None,
        process_collector: Optional[ProcessCollector] = None,
        fim_monitor: Optional[FileIntegrityMonitor] = None,
        client: Optional[AgentClient] = None,
        spool: Optional[EventSpool] = None,
    ):
        self.config = config or AgentConfig.from_env()

        spool_db = self.config.spool_path or ":memory:"
        self.spool = spool or EventSpool(
            db_path=spool_db,
            max_size=self.config.max_spool_size,
            agent_id=self.config.agent_id,
        )

        self.system_collector = system_collector or SystemCollector(
            agent_id=self.config.agent_id,
            agent_version=self.config.agent_version,
        )
        self.process_collector = process_collector or ProcessCollector(
            agent_id=self.config.agent_id,
        )
        self.fim_monitor = fim_monitor or FileIntegrityMonitor(
            agent_id=self.config.agent_id,
            monitored_paths=self.config.monitored_paths,
            spool=self.spool,
        )
        if hasattr(self.fim_monitor, "spool") and self.fim_monitor.spool is None:
            self.fim_monitor.spool = self.spool

        self.client = client or AgentClient(
            server_url=self.config.server_url,
            api_token=self.config.api_token,
            timeout=self.config.request_timeout,
            max_retries=self.config.max_retries,
        )

        self.running: bool = False
        self.last_heartbeat_at: float = 0.0
        self.last_process_scan_at: float = 0.0
        self.last_fim_scan_at: float = 0.0
        self.fim_initialized: bool = False

    def _setup_signals(self) -> None:
        """Register signal handlers for graceful shutdown."""
        def _handle_shutdown(signum, _frame):
            sig_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
            logger.info("Received signal %s, initiating graceful shutdown...", sig_name)
            self.running = False

        try:
            signal.signal(signal.SIGINT, _handle_shutdown)
            signal.signal(signal.SIGTERM, _handle_shutdown)
        except (ValueError, OSError) as exc:
            logger.debug("Signal handling setup skipped (e.g., non-main thread): %s", exc)

    def run_single_cycle(self, force_all: bool = False) -> Dict[str, Any]:
        """Execute one evaluation cycle.

        Parameters:
            force_all: If True, execute heartbeat, process scan, and FIM immediately
                       regardless of elapsed interval (ideal for CLI --once and unit tests).

        Returns:
            Dictionary summarizing tasks performed and detected events.
        """
        now = time.time()
        summary: Dict[str, Any] = {
            "heartbeat_sent": False,
            "process_snapshot_sent": False,
            "fim_synced": False,
            "fim_events_sent": 0,
            "errors": [],
        }

        # 1. Heartbeat & System Metrics Task
        if force_all or (now - self.last_heartbeat_at >= self.config.heartbeat_interval):
            try:
                sys_info = self.system_collector.collect_system_info()
                self.client.send_heartbeat(sys_info)
                self.last_heartbeat_at = now
                summary["heartbeat_sent"] = True
                logger.info("Heartbeat transmitted successfully for agent '%s'", self.config.agent_id)

                # Send system telemetry metrics
                try:
                    if hasattr(self.system_collector, "collect_telemetry_envelope"):
                        telemetry_env = self.system_collector.collect_telemetry_envelope()
                    elif hasattr(self.system_collector, "collect_metrics"):
                        raw_metrics = self.system_collector.collect_metrics()
                        if isinstance(raw_metrics, dict) and "cpu_percent" in raw_metrics:
                            telemetry_env = {
                                "schema_version": "1.0",
                                "message_id": str(uuid.uuid4()),
                                "agent_id": self.config.agent_id,
                                "collected_at": datetime.now(timezone.utc).isoformat(),
                                "payload": raw_metrics,
                            }
                        else:
                            telemetry_env = None
                    else:
                        telemetry_env = None

                    if telemetry_env:
                        self.client.send_system_telemetry(telemetry_env)
                        summary["telemetry_sent"] = True
                        logger.info("System telemetry transmitted successfully for agent '%s'", self.config.agent_id)
                except Exception as t_exc:
                    logger.warning("System telemetry error: %s", t_exc)
            except Exception as exc:
                err_msg = f"Heartbeat error: {exc}"
                logger.warning(err_msg)
                summary["errors"].append(err_msg)

        # 2. Process Snapshot Task
        if force_all or (now - self.last_process_scan_at >= self.config.process_interval):
            try:
                proc_snapshot = self.process_collector.collect_snapshot()
                self.client.send_process_snapshot(proc_snapshot)
                self.last_process_scan_at = now
                summary["process_snapshot_sent"] = True
                logger.info(
                    "Process snapshot transmitted (%d processes)",
                    proc_snapshot.get("payload", {}).get("process_count", 0),
                )
            except Exception as exc:
                err_msg = f"Process snapshot error: {exc}"
                logger.warning(err_msg)
                summary["errors"].append(err_msg)

        # 3. File Integrity Monitoring (FIM) Task
        if force_all or (now - self.last_fim_scan_at >= self.config.fim_interval):
            try:
                # 3a. Drain pending events from local durable spool queue first
                drained_paths = set()
                if self.spool:
                    pending_spool = self.spool.get_pending_events(limit=50)
                    for item in pending_spool:
                        try:
                            self.client.send_security_event(item["envelope"])
                            self.spool.mark_acknowledged(item["message_id"])
                            summary["fim_events_sent"] += 1
                            envelope = item.get("envelope", {})
                            fpath = (
                                envelope.get("payload", {}).get("evidence", {}).get("file_path")
                                or envelope.get("payload", {}).get("file_path")
                                or envelope.get("file_path")
                            )
                            if fpath:
                                drained_paths.add(fpath)
                            logger.info("Spool drained pending FIM event '%s'", item["message_id"])
                        except Exception as p_exc:
                            self.spool.record_failure(item["message_id"])
                            logger.warning("Spool transmission paused on event '%s': %s (will retry)", item["message_id"], p_exc)
                            break

                # 3b. Baseline initialization or delta change scan
                if not self.fim_initialized:
                    file_count = self.fim_monitor.initialize_baseline()
                    sync_payload = self.fim_monitor.get_baseline_sync_payload()
                    self.client.send_file_baselines(sync_payload)
                    self.fim_initialized = True
                    summary["fim_synced"] = True
                    logger.info("Initial FIM baseline established and synced (%d files)", file_count)
                else:
                    scan_res = self.fim_monitor.scan_for_changes() if hasattr(self.fim_monitor, "scan_for_changes") else None
                    if isinstance(scan_res, tuple) and len(scan_res) == 2:
                        new_baseline, changes = scan_res
                    else:
                        changes = self.fim_monitor.check_for_changes()
                        new_baseline = None

                    if changes:
                        sec_events = self.fim_monitor.get_security_events(changes)
                        # Ensure every event has a stable message_id
                        for evt in sec_events:
                            if not evt.get("message_id"):
                                evt["message_id"] = str(uuid.uuid4())

                        # Filter out events whose changes were already transmitted in step 3a
                        events_to_send = []
                        for evt in sec_events:
                            fpath = (
                                evt.get("payload", {}).get("evidence", {}).get("file_path")
                                or evt.get("payload", {}).get("file_path")
                                or evt.get("file_path")
                            )
                            if fpath and fpath in drained_paths:
                                continue
                            events_to_send.append(evt)

                        if events_to_send:
                            # Persist newly detected events in durable SQLite spool queue FIRST
                            if self.spool:
                                self.spool.enqueue_events(events_to_send)

                            all_sent = True
                            last_err = None
                            for evt in events_to_send:
                                try:
                                    self.client.send_security_event(evt)
                                    if self.spool:
                                        self.spool.mark_acknowledged(evt.get("message_id"))
                                    summary["fim_events_sent"] += 1
                                except Exception as evt_exc:
                                    all_sent = False
                                    last_err = str(evt_exc)
                                    if self.spool:
                                        self.spool.record_failure(evt.get("message_id"))
                                    logger.warning("Failed to send FIM event '%s': %s (persisted in spool)", evt.get("message_id"), evt_exc)

                            if all_sent:
                                logger.info("FIM detected and transmitted %d file changes", len(events_to_send))
                                if new_baseline is not None and hasattr(self.fim_monitor, "commit_baseline"):
                                    self.fim_monitor.commit_baseline(new_baseline)
                            else:
                                err_msg = f"FIM scan error: Failed to send FIM event: {last_err or 'network error'}"
                                logger.warning(err_msg)
                                summary["errors"].append(err_msg)
                        else:
                            # All changes already drained and transmitted; advance baseline safely
                            if new_baseline is not None and hasattr(self.fim_monitor, "commit_baseline"):
                                self.fim_monitor.commit_baseline(new_baseline)
                    else:
                        logger.debug("FIM scan clean, no file changes detected")

                self.last_fim_scan_at = now
            except Exception as exc:
                err_msg = f"FIM scan error: {exc}"
                logger.warning(err_msg)
                summary["errors"].append(err_msg)

        return summary

    def start(self) -> None:
        """Start the agent execution loop."""
        self._setup_signals()
        self.running = True

        logger.info("==================================================")
        logger.info("Starting Mini EDR Linux Agent v%s", self.config.agent_version)
        logger.info("Agent ID:    %s", self.config.agent_id)
        logger.info("Server URL:  %s", self.config.server_url)
        logger.info("Monitored:   %s", ", ".join(self.config.monitored_paths))
        logger.info("Heartbeat:   %.1fs | Process: %.1fs | FIM: %.1fs",
                    self.config.heartbeat_interval,
                    self.config.process_interval,
                    self.config.fim_interval)
        logger.info("==================================================")

        # Check initial server connectivity
        if self.client.check_health():
            logger.info("Server connectivity verified (status: ok)")
        else:
            logger.warning("Server is currently unreachable at %s; will retry during collection cycles", self.config.server_url)

        try:
            while self.running:
                self.run_single_cycle()
                # Tick sleep to allow responsive signal interruption
                for _ in range(10):
                    if not self.running:
                        break
                    time.sleep(0.1)
        except Exception as exc:
            logger.exception("Fatal unhandled exception in agent loop: %s", exc)
        finally:
            logger.info("Mini EDR Linux Agent stopped cleanly.")

    def stop(self) -> None:
        """Signal the orchestrator to stop."""
        self.running = False


def main() -> None:
    """CLI entry point for running the Mini EDR Agent."""
    import argparse

    parser = argparse.ArgumentParser(description="Mini EDR Linux Agent")
    parser.add_argument("--once", action="store_true", help="Run a single collection cycle and exit")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--server", type=str, default=None, help="EDR API Server URL")
    parser.add_argument("--agent-id", type=str, default=None, help="Override endpoint agent ID")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    config = AgentConfig.from_env()
    if args.server:
        config.server_url = args.server
    if args.agent_id:
        config.agent_id = args.agent_id

    orchestrator = AgentOrchestrator(config=config)

    if args.once:
        logger.info("Executing single collection cycle (--once)...")
        summary = orchestrator.run_single_cycle(force_all=True)
        logger.info("Cycle finished. Summary: %s", summary)
        sys.exit(0 if not summary["errors"] else 1)

    orchestrator.start()


if __name__ == "__main__":
    main()
