-- Migration 004: card methods are checked by the server, not by a CHECK list (PostgreSQL).
--
-- Why: 003 allowed only test_dev, anon_aadhaar, passport_zk, passport_attested and
-- face_estimate. Phase 2 and 4d add emrtd_attested, philsys_qr_attested,
-- mynumber_attested, mdoc_app and connector:<id>. The server already checks every
-- method name before it stores a card (src/cards/store.ts), so the list goes.
-- Existing rows are untouched. The same change as 004_cards_any_method_sqlite.sql.

ALTER TABLE cards DROP CONSTRAINT IF EXISTS cards_method_check;
ALTER TABLE cards ALTER COLUMN method TYPE VARCHAR(64);
ALTER TABLE cards ADD CONSTRAINT cards_method_length CHECK (length(method) BETWEEN 1 AND 64);
