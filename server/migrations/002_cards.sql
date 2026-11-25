-- Migration 002: Age cards (PostgreSQL)
-- Run after 001_init_nullifiers.sql.
--
-- PostgreSQL schema for age cards (the server applies it; see 003 for the
-- phase 2 changes).
--
-- A card record holds ONLY: card ID, device public key, method, validity,
-- nullifier hash and status (PROTOCOL.md section 2). No personal data.

CREATE TABLE IF NOT EXISTS cards (
    card_id VARCHAR(64) PRIMARY KEY,
    method VARCHAR(32) NOT NULL CHECK (method IN ('test_dev', 'anon_aadhaar', 'passport_zk')),
    assurance_level VARCHAR(32) NOT NULL,
    min_age_certified SMALLINT NOT NULL CHECK (min_age_certified BETWEEN 1 AND 99),
    device_key_alg VARCHAR(8) NOT NULL CHECK (device_key_alg IN ('ES256', 'RS256')),
    device_key_jwk JSONB NOT NULL,
    device_key_thumbprint VARCHAR(64) NOT NULL,
    nullifier_hash VARCHAR(64) NOT NULL REFERENCES nullifiers(nullifier_hash),
    status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cards_nullifier_status ON cards(nullifier_hash, status);
CREATE INDEX IF NOT EXISTS idx_cards_thumbprint ON cards(device_key_thumbprint);

-- The nullifier cap (V18_MAX_CARDS_PER_ID) must be checked and the new card
-- inserted in ONE transaction. Lock the nullifier row first so two requests
-- for the same ID cannot both pass the count:
--   BEGIN;
--   INSERT INTO nullifiers (nullifier_hash, issuer_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;
--   SELECT 1 FROM nullifiers WHERE nullifier_hash = $1 FOR UPDATE;
--   SELECT COUNT(*) FROM cards WHERE nullifier_hash = $1 AND status = 'active' AND valid_until > now();
--   INSERT INTO cards (...) VALUES (...);   -- only if the count is below the cap
--   COMMIT;

COMMENT ON TABLE cards IS 'Age cards: device-bound, anonymous. No personal data.';
COMMENT ON COLUMN cards.device_key_jwk IS 'Device PUBLIC key (JWK). The private key stays in the device secure hardware.';
COMMENT ON COLUMN cards.nullifier_hash IS 'SHA-256 of the method nullifier. Limits active cards per ID without revealing the ID.';
