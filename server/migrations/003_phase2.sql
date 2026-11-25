-- Migration 003: phase 2 (PROTOCOL.md 4c), PostgreSQL.
-- Run after 001_init_nullifiers.sql and 002_cards.sql (the server applies
-- them in order, once, under an advisory lock, so several copies can start
-- at the same time).
--
-- All state lives here so several server copies can run behind a load
-- balancer: cards and nullifiers (long-lived), and challenges, rate limits,
-- pairing sessions, device links, wallet requests and attestation records
-- (short-lived, deleted after they expire). Signing keys are stored
-- encrypted (AES-256-GCM with V18_KEK, or wrapped by a KMS).
-- Times in the new tables are epoch milliseconds (BIGINT).

ALTER TABLE cards DROP CONSTRAINT IF EXISTS cards_method_check;
ALTER TABLE cards ADD CONSTRAINT cards_method_check
    CHECK (method IN ('test_dev', 'anon_aadhaar', 'passport_zk', 'passport_attested', 'face_estimate'));

CREATE TABLE IF NOT EXISTS challenges (
    challenge VARCHAR(64) PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
    rl_key TEXT PRIMARY KEY,
    hits TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);

CREATE TABLE IF NOT EXISTS state_docs (
    kind VARCHAR(16) NOT NULL,
    id VARCHAR(128) NOT NULL,
    data TEXT NOT NULL,
    version INTEGER NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS idx_state_docs_expires ON state_docs(expires_at);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid VARCHAR(64) PRIMARY KEY,
    purpose VARCHAR(16) NOT NULL,
    info TEXT NOT NULL,
    wrapped_private TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_meta (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT NOT NULL
);

COMMENT ON TABLE state_docs IS 'Short-lived protocol state (pairing sessions, device links, wallet requests). No personal data. Deleted soon after expires_at.';
COMMENT ON TABLE signing_keys IS 'Ticket and nullifier signing keys. wrapped_private is encrypted; the plain private key never touches the database.';
