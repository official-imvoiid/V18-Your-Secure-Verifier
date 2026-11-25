-- Migration 003: phase 2 (PROTOCOL.md 4c), SQLite.
--
-- 1. Cards may now also come from passport_attested and face_estimate.
--    SQLite cannot change a CHECK constraint, so the table is rebuilt.
-- 2. All short-lived state moves into the database (it used to live in
--    memory), so the same code runs on SQLite and PostgreSQL:
--    challenges, rate limits, pairing sessions, device links, wallet
--    requests and attestation records ("state_docs"), and signing keys.
-- Times in the new tables are epoch milliseconds.

CREATE TABLE cards_new (
    card_id TEXT PRIMARY KEY,
    method TEXT NOT NULL CHECK (method IN ('test_dev', 'anon_aadhaar', 'passport_zk', 'passport_attested', 'face_estimate')),
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
INSERT INTO cards_new SELECT card_id, method, assurance_level, min_age_certified, device_key_alg, device_key_jwk,
    device_key_thumbprint, nullifier_hash, status, issued_at, valid_until, revoked_at FROM cards;
DROP TABLE cards;
ALTER TABLE cards_new RENAME TO cards;
CREATE INDEX IF NOT EXISTS idx_cards_nullifier_status ON cards(nullifier_hash, status);
CREATE INDEX IF NOT EXISTS idx_cards_thumbprint ON cards(device_key_thumbprint);

CREATE TABLE IF NOT EXISTS challenges (
    challenge TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
    rl_key TEXT PRIMARY KEY,
    hits TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);

CREATE TABLE IF NOT EXISTS state_docs (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    data TEXT NOT NULL,
    version INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS idx_state_docs_expires ON state_docs(expires_at);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    info TEXT NOT NULL,
    wrapped_private TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS server_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
