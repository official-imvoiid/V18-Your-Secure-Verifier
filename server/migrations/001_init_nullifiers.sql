-- Migration 001: Initialize Nullifiers Table for PostgreSQL
-- V18 Privacy-Preserving Nullifier Store

CREATE TABLE IF NOT EXISTS nullifiers (
    nullifier_hash VARCHAR(64) PRIMARY KEY,
    issuer_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nullifiers_issuer_id ON nullifiers(issuer_id);
CREATE INDEX IF NOT EXISTS idx_nullifiers_created_at ON nullifiers(created_at);

COMMENT ON TABLE nullifiers IS 'Anonymous cryptographic hashes preventing one ID from generating unlimited active age cards';
COMMENT ON COLUMN nullifiers.nullifier_hash IS 'SHA-256 hash of (ID secret + Issuer salt), impossible to reverse to real identity';

