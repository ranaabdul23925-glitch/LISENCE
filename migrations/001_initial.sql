-- ShopPOS license server -- PostgreSQL migration 1 (schema version 0 -> 1)
-- Core tables: shops, licenses, license audit logs.
CREATE TABLE IF NOT EXISTS shops (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  local_shop_id TEXT UNIQUE,
  verified_by TEXT,
  verified_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY,
  shop_id TEXT NOT NULL REFERENCES shops(id),
  key_hash TEXT NOT NULL UNIQUE,
  plan_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'suspended', 'cancelled', 'revoked')),
  starts_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  trial_ends_at TEXT,
  intended_local_shop_id TEXT,
  key_redeemed_at TEXT,
  local_shop_id TEXT,
  device_id TEXT,
  activated_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS license_logs (
  id SERIAL PRIMARY KEY,
  license_id TEXT,
  actor_id TEXT,
  event TEXT NOT NULL,
  local_shop_id TEXT,
  device_id TEXT,
  remote_address TEXT,
  created_at TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_license_logs_license_created
  ON license_logs(license_id, created_at);
UPDATE schema_meta SET version = 1 WHERE id = 1;
