-- ShopPOS license server -- PostgreSQL migration 4 (schema version 3 -> 4)
-- Final query indexes and schema version target.
CREATE INDEX IF NOT EXISTS idx_payments_license ON payments(license_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status, submitted_at);
CREATE INDEX IF NOT EXISTS idx_payment_events_payment ON payment_events(payment_id, created_at);
UPDATE schema_meta SET version = 4 WHERE id = 1;
