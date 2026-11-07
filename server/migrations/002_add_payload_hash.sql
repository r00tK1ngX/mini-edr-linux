-- =========================================================
-- Mini EDR - Phase 4 Data Integrity
-- Migration: 002_add_payload_hash
--
-- Adds payload_hash column to process_snapshots to ensure
-- robust canonical JSON SHA-256 deduplication and reject
-- payload collisions under reused message IDs.
-- =========================================================

ALTER TABLE process_snapshots ADD COLUMN payload_hash TEXT;
