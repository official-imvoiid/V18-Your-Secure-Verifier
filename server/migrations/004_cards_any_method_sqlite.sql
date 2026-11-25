-- Migration 004: card methods are checked by the server, not by a CHECK list (SQLite).
--
-- Why: 003 (as first applied on 2026-11-19) allowed only test_dev, anon_aadhaar,
-- passport_zk, passport_attested and face_estimate. Phase 2 and 4d add
-- emrtd_attested, philsys_qr_attested, mynumber_attested, mdoc_app and
-- connector:<id>, so inserting them failed. The server already checks every
-- method name before it stores a card (src/cards/store.ts), so the list goes.
-- SQLite cannot drop a CHECK, so the table is rebuilt. Every existing row is kept.

CREATE TABLE cards_v4 (
    card_id TEXT PRIMARY KEY,
    method TEXT NOT NULL CHECK (length(method) BETWEEN 1 AND 64),
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
INSERT INTO cards_v4 SELECT card_id, method, assurance_level, min_age_certified, device_key_alg, device_key_jwk,
    device_key_thumbprint, nullifier_hash, status, issued_at, valid_until, revoked_at FROM cards;
DROP TABLE cards;
ALTER TABLE cards_v4 RENAME TO cards;
CREATE INDEX IF NOT EXISTS idx_cards_nullifier_status ON cards(nullifier_hash, status);
CREATE INDEX IF NOT EXISTS idx_cards_thumbprint ON cards(device_key_thumbprint);
