-- Migration 002: Age cards (SQLite, local dev and tests)
--
-- A card record holds ONLY: card ID, device public key, method, validity,
-- nullifier hash and status (PROTOCOL.md section 2). No name, birth date,
-- ID number, ID image or face, and nothing about which sites were visited.
-- Times are ISO 8601 UTC strings ("2026-11-09T12:00:00.000Z"), so text
-- comparison orders them correctly.

CREATE TABLE IF NOT EXISTS cards (
    card_id TEXT PRIMARY KEY,
    method TEXT NOT NULL CHECK (method IN ('test_dev', 'anon_aadhaar', 'passport_zk')),
    assurance_level TEXT NOT NULL,
    min_age_certified INTEGER NOT NULL,
    device_key_alg TEXT NOT NULL CHECK (device_key_alg IN ('ES256', 'RS256')),
    device_key_jwk TEXT NOT NULL,
    device_key_thumbprint TEXT NOT NULL,
    nullifier_hash TEXT NOT NULL REFERENCES nullifiers(nullifier_hash),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    issued_at TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_cards_nullifier_status ON cards(nullifier_hash, status);
CREATE INDEX IF NOT EXISTS idx_cards_thumbprint ON cards(device_key_thumbprint);
