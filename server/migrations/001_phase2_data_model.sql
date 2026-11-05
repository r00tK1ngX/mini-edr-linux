-- =========================================================
-- Mini EDR - Phase 2 Data Model
-- Migration: 001_phase2_data_model
--
-- Existing table:
--   endpoints (created in Phase 1)
--
-- New tables:
--   system_metrics
--   process_snapshots
--   process_observations
--   file_baselines
--   security_events
--   alerts
--   alert_events
--
-- schema_migrations is maintained by Migration Runner.
-- This file must not contain BEGIN / COMMIT statements.
-- =========================================================


-- =========================================================
-- 1. SYSTEM METRICS
-- Stores historical system resource measurements.
-- =========================================================

CREATE TABLE system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    message_id TEXT NOT NULL UNIQUE
        CHECK (length(trim(message_id)) > 0),

    schema_version TEXT NOT NULL DEFAULT '1.0',

    agent_id TEXT NOT NULL,

    cpu_percent REAL NOT NULL
        CHECK (cpu_percent >= 0 AND cpu_percent <= 100),

    memory_percent REAL NOT NULL
        CHECK (memory_percent >= 0 AND memory_percent <= 100),

    disk_percent REAL NOT NULL
        CHECK (disk_percent >= 0 AND disk_percent <= 100),

    uptime_seconds REAL NOT NULL
        CHECK (uptime_seconds >= 0),

    collected_at TEXT NOT NULL,

    received_at TEXT NOT NULL,

    FOREIGN KEY (agent_id)
        REFERENCES endpoints(agent_id)
        ON DELETE RESTRICT
);


CREATE INDEX idx_system_metrics_agent_collected
ON system_metrics(agent_id, collected_at DESC);


-- =========================================================
-- 2. PROCESS SNAPSHOTS
-- Stores one record for each process collection cycle.
-- =========================================================

CREATE TABLE process_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    message_id TEXT NOT NULL UNIQUE
        CHECK (length(trim(message_id)) > 0),

    schema_version TEXT NOT NULL DEFAULT '1.0',

    agent_id TEXT NOT NULL,

    process_count INTEGER NOT NULL
        CHECK (process_count >= 0),

    collected_at TEXT NOT NULL,

    received_at TEXT NOT NULL,

    FOREIGN KEY (agent_id)
        REFERENCES endpoints(agent_id)
        ON DELETE RESTRICT
);


CREATE INDEX idx_process_snapshots_agent_collected
ON process_snapshots(agent_id, collected_at DESC);


-- =========================================================
-- 3. PROCESS OBSERVATIONS
-- Stores individual processes inside a snapshot.
--
-- Composite primary key:
--   (snapshot_id, pid)
--
-- PID alone is not globally unique over time.
-- =========================================================

CREATE TABLE process_observations (
    snapshot_id INTEGER NOT NULL,

    pid INTEGER NOT NULL
        CHECK (pid >= 0),

    ppid INTEGER
        CHECK (ppid IS NULL OR ppid >= 0),

    process_name TEXT NOT NULL
        CHECK (length(trim(process_name)) > 0),

    username TEXT,

    exe_path TEXT,

    cpu_percent REAL
        CHECK (cpu_percent IS NULL OR cpu_percent >= 0),

    memory_percent REAL
        CHECK (
            memory_percent IS NULL
            OR (memory_percent >= 0 AND memory_percent <= 100)
        ),

    rss_bytes INTEGER
        CHECK (rss_bytes IS NULL OR rss_bytes >= 0),

    process_started_at TEXT,

    PRIMARY KEY (snapshot_id, pid),

    FOREIGN KEY (snapshot_id)
        REFERENCES process_snapshots(id)
        ON DELETE CASCADE
);


CREATE INDEX idx_process_observations_name
ON process_observations(process_name);


CREATE INDEX idx_process_observations_exe_path
ON process_observations(exe_path);


-- =========================================================
-- 4. FILE BASELINES
-- Stores known file integrity information.
--
-- A missing file remains in the baseline so that its
-- deletion can be represented without losing its last hash.
-- =========================================================

CREATE TABLE file_baselines (
    agent_id TEXT NOT NULL,

    file_path TEXT NOT NULL
        CHECK (length(trim(file_path)) > 0),

    sha256 TEXT NOT NULL
        CHECK (
            length(sha256) = 64
            AND sha256 NOT GLOB '*[^0-9a-f]*'
        ),

    file_size_bytes INTEGER NOT NULL
        CHECK (file_size_bytes >= 0),

    mtime_ns INTEGER NOT NULL
        CHECK (mtime_ns >= 0),

    file_mode INTEGER NOT NULL
        CHECK (file_mode >= 0 AND file_mode <= 4095),

    state TEXT NOT NULL DEFAULT 'present'
        CHECK (state IN ('present', 'missing')),

    first_seen_at TEXT NOT NULL,

    last_seen_at TEXT NOT NULL,

    last_checked_at TEXT NOT NULL,

    PRIMARY KEY (agent_id, file_path),

    FOREIGN KEY (agent_id)
        REFERENCES endpoints(agent_id)
        ON DELETE RESTRICT
);


CREATE INDEX idx_file_baselines_agent_state
ON file_baselines(agent_id, state);


-- =========================================================
-- 5. SECURITY EVENTS
-- Stores security-relevant events from the Agent,
-- Detection Engine, or Server.
-- =========================================================

CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    message_id TEXT NOT NULL UNIQUE
        CHECK (length(trim(message_id)) > 0),

    schema_version TEXT NOT NULL DEFAULT '1.0',

    agent_id TEXT NOT NULL,

    event_type TEXT NOT NULL
        CHECK (length(trim(event_type)) > 0),

    severity TEXT NOT NULL DEFAULT 'info'
        CHECK (
            severity IN (
                'info',
                'low',
                'medium',
                'high',
                'critical'
            )
        ),

    source TEXT NOT NULL
        CHECK (source IN ('agent', 'detection', 'server')),

    title TEXT NOT NULL
        CHECK (length(trim(title)) > 0),

    description TEXT,

    evidence_json TEXT NOT NULL DEFAULT '{}',

    occurred_at TEXT NOT NULL,

    received_at TEXT NOT NULL,

    fingerprint TEXT,

    FOREIGN KEY (agent_id)
        REFERENCES endpoints(agent_id)
        ON DELETE RESTRICT
);


CREATE INDEX idx_security_events_agent_occurred
ON security_events(agent_id, occurred_at DESC);


CREATE INDEX idx_security_events_severity_occurred
ON security_events(severity, occurred_at DESC);


CREATE INDEX idx_security_events_type
ON security_events(event_type);


CREATE INDEX idx_security_events_fingerprint
ON security_events(fingerprint);


-- =========================================================
-- 6. ALERTS
-- Stores incidents requiring administrator attention.
-- =========================================================

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    alert_key TEXT NOT NULL UNIQUE
        CHECK (length(trim(alert_key)) > 0),

    agent_id TEXT NOT NULL,

    rule_id TEXT NOT NULL
        CHECK (length(trim(rule_id)) > 0),

    title TEXT NOT NULL
        CHECK (length(trim(title)) > 0),

    description TEXT,

    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'info',
                'low',
                'medium',
                'high',
                'critical'
            )
        ),

    status TEXT NOT NULL DEFAULT 'new'
        CHECK (
            status IN (
                'new',
                'acknowledged',
                'resolved'
            )
        ),

    first_seen_at TEXT NOT NULL,

    last_seen_at TEXT NOT NULL,

    created_at TEXT NOT NULL,

    updated_at TEXT NOT NULL,

    acknowledged_at TEXT,

    resolved_at TEXT,

    resolution_note TEXT,

    CHECK (
        status != 'acknowledged'
        OR acknowledged_at IS NOT NULL
    ),

    CHECK (
        status != 'resolved'
        OR resolved_at IS NOT NULL
    ),

    FOREIGN KEY (agent_id)
        REFERENCES endpoints(agent_id)
        ON DELETE RESTRICT
);


CREATE INDEX idx_alerts_status_severity
ON alerts(status, severity, last_seen_at DESC);


CREATE INDEX idx_alerts_agent_status
ON alerts(agent_id, status, last_seen_at DESC);


-- =========================================================
-- 7. ALERT EVENTS
-- Many-to-many relationship:
--
--   One Alert can be associated with multiple Events.
--   One Event can be associated with multiple Alerts.
-- =========================================================

CREATE TABLE alert_events (
    alert_id INTEGER NOT NULL,

    event_id INTEGER NOT NULL,

    linked_at TEXT NOT NULL,

    PRIMARY KEY (alert_id, event_id),

    FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    FOREIGN KEY (event_id)
        REFERENCES security_events(id)
        ON DELETE CASCADE
);


CREATE INDEX idx_alert_events_event
ON alert_events(event_id);

