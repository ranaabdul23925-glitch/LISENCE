-- ShopPOS license server -- PostgreSQL migration 3 (schema version 2 -> 3)
-- Additional plan, shop and license columns plus partial unique indexes.
ALTER TABLE plans ADD COLUMN IF NOT EXISTS features_json TEXT;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS max_devices INTEGER;
ALTER TABLE plans ADD COLUMN IF NOT EXISTS max_staff INTEGER;
ALTER TABLE shops ADD COLUMN IF NOT EXISTS local_shop_id TEXT;
ALTER TABLE shops ADD COLUMN IF NOT EXISTS verified_by TEXT;
ALTER TABLE shops ADD COLUMN IF NOT EXISTS verified_at TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS intended_local_shop_id TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS key_redeemed_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_shops_local_shop_id
  ON shops(local_shop_id) WHERE local_shop_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_provider_txn
  ON payments(provider_transaction_id) WHERE provider_transaction_id IS NOT NULL;
UPDATE schema_meta SET version = 3 WHERE id = 1;
