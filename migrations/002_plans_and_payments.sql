-- ShopPOS license server -- PostgreSQL migration 2 (schema version 1 -> 2)
-- Subscription plans, manual/gateway payments, payment events, gateway webhook events.
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  interval TEXT NOT NULL CHECK (interval IN ('monthly', 'yearly')),
  price_minor INTEGER NOT NULL CHECK (price_minor >= 0),
  currency TEXT NOT NULL,
  trial_days INTEGER NOT NULL CHECK (trial_days BETWEEN 0 AND 365),
  grace_days INTEGER NOT NULL CHECK (grace_days BETWEEN 0 AND 60),
  available INTEGER NOT NULL CHECK (available IN (0, 1)),
  features_json TEXT,
  max_devices INTEGER,
  max_staff INTEGER,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  shop_id TEXT NOT NULL REFERENCES shops(id),
  license_id TEXT NOT NULL REFERENCES licenses(id),
  plan_id TEXT NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('manual', 'gateway')),
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'failed', 'refunded', 'disputed')),
  amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
  currency TEXT NOT NULL,
  reference TEXT NOT NULL,
  reference_key TEXT NOT NULL UNIQUE,
  provider TEXT,
  provider_transaction_id TEXT,
  note TEXT,
  decision_reason TEXT,
  submitted_by_device TEXT,
  submitted_at TEXT NOT NULL,
  decided_by TEXT,
  decided_at TEXT,
  applied_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payment_events (
  id SERIAL PRIMARY KEY,
  payment_id TEXT,
  event TEXT NOT NULL,
  actor_id TEXT,
  remote_address TEXT,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_events (
  provider TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT,
  provider_transaction_id TEXT,
  payment_id TEXT,
  result TEXT NOT NULL,
  remote_address TEXT,
  received_at TEXT NOT NULL,
  PRIMARY KEY (provider, event_id)
);
CREATE INDEX IF NOT EXISTS idx_payments_license ON payments(license_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status, submitted_at);
CREATE INDEX IF NOT EXISTS idx_payment_events_payment ON payment_events(payment_id, created_at);
UPDATE schema_meta SET version = 2 WHERE id = 1;
