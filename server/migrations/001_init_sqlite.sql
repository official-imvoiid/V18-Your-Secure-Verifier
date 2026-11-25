-- Migration 001: Initialize Nullifiers Table for SQLite (Local Dev & Unit Tests)

CREATE TABLE IF NOT EXISTS nullifiers (
    nullifier_hash TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nullifiers_issuer_id ON nullifiers(issuer_id);

