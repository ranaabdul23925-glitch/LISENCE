"use strict";

// ShopPOS license server -- PostgreSQL adapter.
//
// This module provides PostgresLicenseService, a drop-in replacement for the
// SQLite-backed LicenseService (license-server.cjs) that stores the same
// license, shop, plan, payment, payment-event, gateway-event and audit-log
// records in PostgreSQL via node-postgres (`pg`). It uses a connection pool,
// runs schema migrations, performs multi-statement operations inside
// transactions, and uses row-level locking (`FOR UPDATE`) for concurrency
// safety (for example, license activation).
//
// Ed25519 license signing is identical to the SQLite service: the same
// private key signs the same claims shape, so entitlements issued by either
// storage backend verify against the same configured public key.
//
// PostgreSQL is intentionally NOT the default. The existing
// LicenseService (sql.js/WASM SQLite) remains the active implementation and
// is unchanged. This adapter is opt-in: construct PostgresLicenseService
// directly (or use createPostgresLicenseServer) and point it at an isolated
// test database. Never connect to the real Supabase project from here.

const { Pool } = require("pg");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  parsePlans,
  parseAdminUsers,
  statusFor,
  validateServerConfiguration,
  validatePostgresServerConfiguration
} = require("./license-server.cjs");

const SCHEMA_VERSION = 4;
const MIGRATION_DIR = path.join(__dirname, "migrations");
const PAYMENT_STATUSES = new Set(["pending", "approved", "rejected", "failed", "refunded", "disputed"]);
const SUBSCRIPTION_GRACE_DAYS = 7;

// Fixed business rule: every subscription grace period lasts exactly 7 days
// after expiry.
function addPeriod(isoDate, interval) {
  const date = new Date(isoDate);
  const day = date.getUTCDate();
  date.setUTCDate(1);
  date.setUTCMonth(date.getUTCMonth() + (interval === "yearly" ? 12 : 1));
  const lastDay = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
  date.setUTCDate(Math.min(day, lastDay));
  return date.toISOString();
}

function validShopId(value) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function assertShopId(value, label = "Shop ID") {
  if (!validShopId(value)) throw new Error(`${label} must be a valid ShopPOS UUID.`);
  return value.toLowerCase();
}

function decodeToken(token) {
  if (typeof token !== "string") throw new Error("A signed license token is required.");
  const parts = token.split(".");
  if (parts.length !== 2) throw new Error("Invalid license token.");
  try {
    return { payload: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")), encoded: parts[0], signature: Buffer.from(parts[1], "base64url") };
  } catch {
    throw new Error("Invalid license token.");
  }
}

function loadMigrations() {
  const files = fs.readdirSync(MIGRATION_DIR).filter(name => /^\d+_.*\.sql$/.test(name)).sort();
  return files.map(file => {
    const version = Number(file.split("_", 1)[0]);
    return { version, file, sql: fs.readFileSync(path.join(MIGRATION_DIR, file), "utf8") };
  });
}

function assertText(value, label, maxLength = 200) {
  if (typeof value !== "string" || !value.trim() || value.length > maxLength) {
    throw new Error(`${label} is required and must be at most ${maxLength} characters.`);
  }
  return value.trim();
}

class PostgresLicenseService {
  constructor({
    databaseUrl,
    plans,
    privateKey,
    offlineGraceDays = 7,
    now = () => Date.now(),
    max = 10
  } = {}) {
    if (!databaseUrl || typeof databaseUrl !== "string") {
      throw new Error("PostgreSQL database URL is required.");
    }
    if (!Number.isInteger(offlineGraceDays) || offlineGraceDays < 0 || offlineGraceDays > 90) {
      throw new Error("LICENSE_OFFLINE_GRACE_DAYS must be between 0 and 90.");
    }
    this.databaseUrl = databaseUrl;
    this.pool = new Pool({ connectionString: databaseUrl, max });
    this.plans = parsePlans(plans);
    this.privateKey = crypto.createPrivateKey(privateKey);
    if (this.privateKey.asymmetricKeyType !== "ed25519") throw new Error("LICENSE_SIGNING_PRIVATE_KEY must be an Ed25519 private key.");
    this.publicKey = crypto.createPublicKey(this.privateKey);
    this.offlineGraceDays = offlineGraceDays;
    this.now = now;
    this.closed = false;
    this._schemaReady = null;
    // Schema initialization is performed lazily and safely by schemaReady() or
    // ensureSchema(). The constructor deliberately does not run migrations so
    // offline-only methods (signing, verification, renewal maths) do not open
    // a database connection, and concurrent initialization is serialized.
  }

  async schemaReady() {
    if (!this._schemaReady) {
      const promise = this.ensureSchema().then(
        (version) => {
          this._schemaReady = Promise.resolve(version);
          return version;
        },
        (error) => {
          this._schemaReady = null; // allow retry after a failed initialization
          throw error;
        }
      );
      this._schemaReady = promise;
    }
    return this._schemaReady;
  }

  async ensureSchema() {
    if (this.closed) throw new Error("The license database is closed.");
    // Serialize concurrent initialization: return the same in-flight promise.
    if (this._schemaInitializing) return this._schemaInitializing;
    // Return cached successful result without re-running migrations.
    if (this._schemaInitialized === true) return this._schemaVersion;
    this._schemaInitializing = this._performSchemaInitialization();
    try {
      const version = await this._schemaInitializing;
      this._schemaInitialized = true;
      this._schemaVersion = version;
      return version;
    } finally {
      // Allow a future call to retry after a failed initialization.
      this._schemaInitializing = null;
    }
  }

  async _performSchemaInitialization() {
    // schema_meta tracks the applied schema version (PostgreSQL has no PRAGMA user_version).
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS schema_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL DEFAULT 0
      );
      INSERT INTO schema_meta (id, version) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;
    `);
    const { rows } = await this.pool.query("SELECT version FROM schema_meta WHERE id = 1");
    let version = Number(rows[0]?.version ?? 0);
    const migrations = loadMigrations();
    for (const migration of migrations) {
      if (migration.version <= version) continue;
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(migration.sql);
        await client.query("COMMIT");
        version = migration.version;
      } catch (error) {
        try { await client.query("ROLLBACK"); } catch {}
        throw new Error(`PostgreSQL migration ${migration.file} failed: ${error.message}`);
      } finally {
        client.release();
      }
    }
    // Seed plans idempotently (only when the plans table is empty), mirroring
    // the SQLite LicenseService.seedPlans() behavior. Never overwrites plans an
    // administrator has configured.
    await this.seedPlansIfEmpty();
    return version;
  }

  async seedPlansIfEmpty() {
    const existing = await this.query("SELECT id FROM plans LIMIT 1");
    if (existing) return;
    const now = new Date(this.now()).toISOString();
    for (const plan of this.plans.values()) {
      await this.pool.query(
        `INSERT INTO plans (id, name, interval, price_minor, currency, trial_days, grace_days, available, features_json, max_devices, max_staff, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (id) DO NOTHING`,
        [
          plan.id, plan.name, plan.interval, plan.priceMinor, plan.currency,
          plan.trialDays, plan.graceDays, plan.available ? 1 : 0,
          plan.features ? JSON.stringify(plan.features) : null,
          plan.maxDevices ?? null, plan.maxStaff ?? null, now
        ]
      );
    }
  }

  async schemaReady() {
    if (!this._schemaReady) {
      const promise = this.ensureSchema().then(
        (version) => {
          this._schemaReady = Promise.resolve(version);
          return version;
        },
        (error) => {
          this._schemaReady = null; // allow retry after a failed initialization
          throw error;
        }
      );
      this._schemaReady = promise;
    }
    return this._schemaReady;
  }

  async healthCheck() {
    const start = Date.now();
    await this.pool.query("SELECT 1 AS ok");
    const { rows } = await this.pool.query("SELECT version FROM schema_meta WHERE id = 1");
    return {
      ok: true,
      service: "shoppos-license-server-postgres",
      schemaVersion: Number(rows[0]?.version ?? 0),
      targetSchemaVersion: SCHEMA_VERSION,
      latencyMs: Date.now() - start
    };
  }

  async query(sql, values = []) {
    const result = await this.pool.query(sql, values);
    return result.rows[0] || undefined;
  }

  async all(sql, values = []) {
    const result = await this.pool.query(sql, values);
    return result.rows;
  }

  async run(sql, values = []) {
    return this.pool.query(sql, values);
  }

  async transaction(fn) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try { await client.query("ROLLBACK"); } catch {}
      throw error;
    } finally {
      client.release();
    }
  }

  logInsert(client, event, { licenseId = null, actorId = null, localShopId = null, deviceId = null, remoteAddress = null, detail = "" } = {}) {
    return client.query(
      `INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [licenseId, actorId, event, localShopId, deviceId, remoteAddress, new Date(this.now()).toISOString(), String(detail).slice(0, 300)]
    );
  }

  async getLicense(licenseId) {
    const row = await this.query(`
      SELECT licenses.*, shops.name AS shop_name
      FROM licenses JOIN shops ON shops.id = licenses.shop_id WHERE licenses.id = $1
    `, [licenseId]);
    if (!row) throw new Error("License was not found.");
    const plan = this.plans.get(row.plan_id);
    if (!plan) throw new Error("The license references a plan that is no longer configured.");
    return { row, plan };
  }

  licenseView(row, plan, now) {
    return {
      licenseId: row.id,
      shopId: row.shop_id,
      shopName: row.shop_name,
      planId: plan.id,
      planName: plan.name,
      interval: plan.interval,
      priceMinor: plan.priceMinor,
      currency: plan.currency,
      status: statusFor(row, plan, now),
      startsAt: row.starts_at,
      expiresAt: row.expires_at,
      trialEndsAt: row.trial_ends_at ?? undefined,
      activatedAt: row.activated_at ?? undefined,
      localShopId: row.local_shop_id ?? undefined,
      intendedLocalShopId: row.intended_local_shop_id ?? undefined,
      deviceId: row.device_id ?? undefined,
      redeemedAt: row.key_redeemed_at ?? undefined
    };
  }

  sign(row, plan, localShopId, deviceId) {
    const claims = {
      version: 1,
      licenseId: row.id,
      shopId: row.shop_id,
      localShopId,
      deviceId,
      shopName: row.shop_name,
      planId: plan.id,
      planName: plan.name,
      interval: plan.interval,
      priceMinor: plan.priceMinor,
      currency: plan.currency,
      status: statusFor(row, plan, this.now()),
      startsAt: row.starts_at,
      expiresAt: row.expires_at,
      trialEndsAt: row.trial_ends_at ?? null,
      graceDays: plan.graceDays,
      offlineGraceDays: this.offlineGraceDays,
      issuedAt: new Date(this.now()).toISOString()
    };
    const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signature = crypto.sign(null, Buffer.from(encoded), this.privateKey).toString("base64url");
    return `${encoded}.${signature}`;
  }

  verify(token) {
    const decoded = decodeToken(token);
    if (!crypto.verify(null, Buffer.from(decoded.encoded), this.publicKey, decoded.signature) ||
        !decoded.payload || decoded.payload.version !== 1) {
      throw new Error("Invalid license token signature.");
    }
    return decoded.payload;
  }

  async createShop(input, { actorId } = {}) {
    const shopName = assertText(input.shopName, "Shop name", 120);
    const plan = this.plans.get(assertText(input.planId, "Plan ID", 40));
    if (!plan || !plan.available) throw new Error("Choose an available configured subscription plan.");
    const now = new Date(this.now()).toISOString();
    const shopId = crypto.randomUUID();
    const licenseId = crypto.randomUUID();
    const licenseKey = `SP-${crypto.randomBytes(24).toString("base64url")}`;
    const trialEndsAt = plan.trialDays ? new Date(this.now() + plan.trialDays * 86400000).toISOString() : null;
    const expiresAt = trialEndsAt ?? addPeriod(now, plan.interval);
    return this.transaction(async (client) => {
      await client.query("INSERT INTO shops (id, name, created_at) VALUES ($1, $2, $3)", [shopId, shopName, now]);
      await client.query(`
        INSERT INTO licenses (id, shop_id, key_hash, plan_id, state, starts_at, expires_at, trial_ends_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9)
      `, [licenseId, shopId, crypto.createHash("sha256").update(licenseKey).digest("hex"), plan.id, now, expiresAt, trialEndsAt, now, now]);
      await this.logInsert(client, "license_created", { licenseId, actorId });
      const view = this.licenseView({ id: licenseId, shop_id: shopId, shop_name: shopName, plan_id: plan.id }, plan, this.now());
      return { ...view, licenseKey };
    });
  }

  async registerExistingShop({ localShopId, shopName, confirmationShopId }, { actorId } = {}) {
    const shopId = assertShopId(localShopId, "Existing ShopPOS Shop ID");
    if (assertShopId(confirmationShopId, "Confirmation Shop ID") !== shopId) {
      throw new Error("Confirm the exact ShopPOS Shop ID before registering it.");
    }
    const name = assertText(shopName, "Shop name", 120);
    const serverShopId = crypto.randomUUID();
    const now = new Date(this.now()).toISOString();
    try {
      await this.pool.query(
        "INSERT INTO shops (id, name, local_shop_id, verified_by, verified_at, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        [serverShopId, name, shopId, actorId, now, now]
      );
      await this.pool.query(
        "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        [null, actorId, "shop_registered", shopId, null, null, now, "admin_attested_existing_shop"]
      );
    } catch (error) {
      if (/unique violation.*shops_local_shop_id_key|duplicate key.*unique constraint.*local_shop_id/i.test(error.message)) {
        throw new Error("That ShopPOS Shop ID is already registered.");
      }
      throw error;
    }
    return this.getShop(serverShopId);
  }

  async getShop(shopId) {
    return this.query(`
      SELECT s.id, s.name, s.local_shop_id AS localShopId, s.verified_by AS verifiedBy,
        s.verified_at AS verifiedAt, s.created_at AS createdAt,
        COUNT(l.id) AS licenseCount
      FROM shops s LEFT JOIN licenses l ON l.shop_id = s.id
      WHERE s.id = $1 GROUP BY s.id
    `, [shopId]);
  }

  async listShops() {
    return this.all(`
      SELECT s.id, s.name, s.local_shop_id AS localShopId, s.verified_by AS verifiedBy,
        s.verified_at AS verifiedAt, s.created_at AS createdAt,
        COUNT(l.id) AS licenseCount,
        MAX(l.created_at) AS latestLicenseCreatedAt
      FROM shops s LEFT JOIN licenses l ON l.shop_id = s.id
      GROUP BY s.id ORDER BY s.created_at DESC
    `);
  }

  async createLicenseForShop(shopId, input, { actorId } = {}) {
    const shop = await this.getShop(assertShopId(shopId, "Server Shop ID"));
    if (!shop) throw new Error("Registered server shop was not found.");
    if (!shop.localShopId) throw new Error("Register and verify the ShopPOS Shop ID before issuing a bound license.");
    if (assertShopId(input.confirmedLocalShopId, "Confirmation Shop ID") !== shop.localShopId) {
      throw new Error("Confirm the exact registered ShopPOS Shop ID before issuing a license.");
    }
    const plan = this.plans.get(assertText(input.planId, "Plan ID", 40));
    if (!plan || !plan.available) throw new Error("Choose an available configured subscription plan.");
    const nowValue = this.now();
    const now = new Date(nowValue).toISOString();
    let expiresAt;
    let trialEndsAt = null;
    if (input.expiresAt !== undefined && input.expiresAt !== null && input.expiresAt !== "") {
      if (typeof input.expiresAt !== "string" || !Number.isFinite(Date.parse(input.expiresAt)) ||
          new Date(Date.parse(input.expiresAt)).toISOString() !== input.expiresAt ||
          Date.parse(input.expiresAt) <= nowValue) {
        throw new Error("A custom license expiration must be a future ISO timestamp.");
      }
      expiresAt = input.expiresAt;
    } else {
      trialEndsAt = plan.trialDays ? new Date(nowValue + plan.trialDays * 86400000).toISOString() : null;
      expiresAt = trialEndsAt ?? addPeriod(now, plan.interval);
    }
    const licenseId = crypto.randomUUID();
    const licenseKey = `SP-${crypto.randomBytes(24).toString("base64url")}`;
    try {
      await this.pool.query(`
        INSERT INTO licenses (
          id, shop_id, key_hash, plan_id, state, starts_at, expires_at, trial_ends_at,
          intended_local_shop_id, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10)
      `, [
        licenseId, shop.id, crypto.createHash("sha256").update(licenseKey).digest("hex"),
        plan.id, now, expiresAt, trialEndsAt, shop.localShopId, now, now
      ]);
      await this.pool.query(
        "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        [licenseId, actorId, "license_created", shop.localShopId, null, null, now, input.expiresAt ? "custom_expiration" : "configured_plan_term"]
      );
    } catch (error) {
      if (/unique violation.*licenses_key_hash_key/i.test(error.message)) {
        throw new Error("A license with this key already exists.");
      }
      throw error;
    }
    return { ...this.licenseView({ id: licenseId, shop_id: shop.id, shop_name: shop.name, plan_id: plan.id, local_shop_id: shop.localShopId, intended_local_shop_id: shop.localShopId }, plan, this.now()), licenseKey };
  }

  async updatePlan(input, { actorId } = {}) {
    const plan = [...parsePlans([input]).values()][0];
    // Fixed business decision: the subscription grace period is exactly 7 days
    // for every plan.
    plan.graceDays = SUBSCRIPTION_GRACE_DAYS;
    let maxDevices = null;
    let maxStaff = null;
    if (input.maxDevices !== undefined && input.maxDevices !== "" && input.maxDevices !== null) {
      maxDevices = Number(input.maxDevices);
    }
    if (input.maxStaff !== undefined && input.maxStaff !== "" && input.maxStaff !== null) {
      maxStaff = Number(input.maxStaff);
    }
    if ((maxDevices !== null && (!Number.isSafeInteger(maxDevices) || maxDevices < 0)) ||
        (maxStaff !== null && (!Number.isSafeInteger(maxStaff) || maxStaff < 0))) {
      throw new Error("Plan device and staff limits, when provided, must be non-negative integers.");
    }
    const featuresJson = input.features
      ? JSON.stringify(String(input.features).slice(0, 300).split(/[;\n,]/).map(item => item.trim()).filter(Boolean))
      : null;
    const now = new Date(this.now()).toISOString();
    await this.pool.query(`
      INSERT INTO plans (id, name, interval, price_minor, currency, trial_days, grace_days, available, features_json, max_devices, max_staff, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name, interval = excluded.interval, price_minor = excluded.price_minor,
        currency = excluded.currency, trial_days = excluded.trial_days,
        grace_days = excluded.grace_days, available = excluded.available,
        features_json = excluded.features_json, max_devices = excluded.max_devices,
        max_staff = excluded.max_staff, updated_at = excluded.updated_at
    `, [
      plan.id, plan.name, plan.interval, plan.priceMinor, plan.currency,
      plan.trialDays, plan.graceDays, plan.available ? 1 : 0,
      featuresJson, maxDevices, maxStaff, now
    ]);
    this.plans = this.loadPlans();
    await this.pool.query(
      "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [null, actorId, "plan_updated", null, null, null, now, plan.id]
    );
    return plan;
  }

  async loadPlans() {
    const rows = await this.all("SELECT * FROM plans ORDER BY name COLLATE NOCASE");
    return new Map(rows.map(row => [row.id, {
      id: row.id,
      name: row.name,
      interval: row.interval,
      priceMinor: row.price_minor,
      currency: row.currency,
      trialDays: row.trial_days,
      graceDays: row.grace_days,
      available: row.available === 1,
      features: row.features_json ? JSON.parse(row.features_json) : [],
      maxDevices: row.max_devices ?? null,
      maxStaff: row.max_staff ?? null
    }]));
  }

  async listPlans() {
    return [...this.plans.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  // Documented renewal-date rule: a renewal extends the subscription from the
  // later of the current time and the existing expiry, so a renewal paid
  // before (or during) expiry never loses unused subscription time. If the
  // extended term would still lie in the past (a deeply expired subscription),
  // the entitlement starts a fresh full term at the time the renewal was
  // recorded. All date arithmetic uses UTC calendar months (month-end safe).
  renewalExpiry(row, plan) {
    const nowMs = this.now();
    const anchor = Math.max(nowMs, Date.parse(row.expires_at));
    let expiresAt = addPeriod(new Date(anchor).toISOString(), plan.interval);
    if (Date.parse(expiresAt) <= nowMs) {
      expiresAt = addPeriod(new Date(nowMs).toISOString(), plan.interval);
    }
    return { anchor, expiresAt };
  }

  async applyRenewal(licenseId, planId, { actorId = null, paymentId = null } = {}) {
    const { row, plan } = await this.getLicense(licenseId);
    if (plan.id !== planId) throw new Error("The payment plan no longer matches the license plan.");
    if (row.state !== "active") throw new Error("Only an active license can be renewed. Reactivate a suspended license first.");
    const { expiresAt } = this.renewalExpiry(row, plan);
    const now = new Date(this.now()).toISOString();
    const guard = paymentId ? " AND NOT EXISTS (SELECT 1 FROM payments WHERE id = $4 AND applied_at IS NOT NULL)" : "";
    const values = paymentId ? [expiresAt, now, licenseId, paymentId] : [expiresAt, now, licenseId];
    const result = await this.pool.query(
      `UPDATE licenses SET expires_at = $1, trial_ends_at = NULL, updated_at = $2
        WHERE id = $3 AND state = 'active'${guard}`,
      values
    );
    if (result.rowCount !== 1) {
      throw new Error(paymentId
        ? "The payment was already applied, or the license is no longer active."
        : "The license is no longer active.");
    }
    await this.pool.query(
      "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [licenseId, actorId, "renewal", null, null, null, new Date(this.now()).toISOString(), paymentId ? `payment:${paymentId}` : "admin_manual"]
    );
    return this.view(licenseId);
  }

  async renew(licenseId, { actorId } = {}) {
    const { plan } = await this.getLicense(licenseId);
    return this.applyRenewal(licenseId, plan.id, { actorId });
  }

  async activate({ licenseKey, localShopId, deviceId, remoteAddress }) {
    const normalizedKey = assertText(licenseKey, "License key", 100);
    const shopId = assertShopId(localShopId, "Local shop ID");
    const device = assertText(deviceId, "Installation ID", 80);
    let failedLicenseId;
    let failureDetail = "invalid_key";
    try {
      return await this.transaction(async (client) => {
        // Row-level lock prevents two concurrent activations of the same key.
        const row = await client.query(`
          SELECT licenses.*, shops.name AS shop_name FROM licenses
          JOIN shops ON shops.id = licenses.shop_id
          WHERE licenses.key_hash = $1
          FOR UPDATE
        `, [crypto.createHash("sha256").update(normalizedKey).digest("hex")]);
        if (!row.rows[0]) throw new Error("The license key is invalid.");
        const licenseRow = row.rows[0];
        failedLicenseId = licenseRow.id;
        const plan = this.plans.get(licenseRow.plan_id);
        if (!plan) throw new Error("The license plan is no longer configured.");
        const currentStatus = statusFor(licenseRow, plan, this.now());
        if (licenseRow.key_redeemed_at) {
          failureDetail = "key_already_redeemed";
          throw new Error("This activation key has already been redeemed.");
        }
        if (licenseRow.state !== "active" || currentStatus === "expired") {
          failureDetail = currentStatus;
          throw new Error(`This license is ${currentStatus}.`);
        }
        if (licenseRow.intended_local_shop_id && licenseRow.intended_local_shop_id !== shopId) {
          failureDetail = "shop_binding_mismatch";
          throw new Error("This license was issued for a different ShopPOS shop.");
        }
        if ((licenseRow.local_shop_id && licenseRow.local_shop_id !== shopId) || (licenseRow.device_id && licenseRow.device_id !== device)) {
          failureDetail = "installation_binding_mismatch";
          throw new Error("This license is already bound to another shop installation.");
        }
        const now = new Date(this.now()).toISOString();
        const update = await client.query(`
          UPDATE licenses SET local_shop_id = $1, device_id = $2,
            activated_at = COALESCE(activated_at, $3), key_redeemed_at = $4, updated_at = $5
          WHERE id = $6 AND key_redeemed_at IS NULL
        `, [shopId, device, now, now, now, licenseRow.id]);
        if (update.rowCount !== 1) {
          failureDetail = "key_already_redeemed";
          throw new Error("This activation key has already been redeemed.");
        }
        await this.logInsert(client, "activation_succeeded", {
          licenseId: licenseRow.id, actorId: "licensee", localShopId: shopId, deviceId: device, remoteAddress
        });
        const updated = (await this.getLicense(licenseRow.id)).row;
        return { token: this.sign(updated, plan, shopId, device), status: this.licenseView(updated, plan, this.now()) };
      });
    } catch (error) {
      await this.pool.query(
        "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        [failedLicenseId, "licensee", "activation_failed", shopId, device, remoteAddress, new Date(this.now()).toISOString(), failureDetail]
      );
      throw error;
    }
  }

  async status({ token, localShopId, deviceId, remoteAddress }) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) throw new Error("This license belongs to a different shop installation.");
    const { row, plan } = await this.getLicense(payload.licenseId);
    if (row.shop_id !== payload.shopId || row.local_shop_id !== shopId || row.device_id !== device) {
      throw new Error("This license is no longer activated for this shop installation.");
    }
    await this.pool.query(
      "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [row.id, "licensee", "status_check", shopId, device, remoteAddress, new Date(this.now()).toISOString(), statusFor(row, plan, this.now())]
    );
    return { token: this.sign(row, plan, shopId, device), status: this.licenseView(row, plan, this.now()) };
  }

  async deactivate({ token, localShopId, deviceId, remoteAddress }) {
    const payload = this.verify(token);
    if (payload.localShopId !== localShopId || payload.deviceId !== deviceId) throw new Error("This license belongs to a different shop installation.");
    const { row } = await this.getLicense(payload.licenseId);
    if (row.local_shop_id !== localShopId || row.device_id !== deviceId) throw new Error("This license is no longer activated for this installation.");
    await this.pool.query(
      "UPDATE licenses SET local_shop_id = NULL, device_id = NULL, activated_at = NULL, updated_at = $1 WHERE id = $2",
      [new Date(this.now()).toISOString(), row.id]
    );
    await this.pool.query(
      "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [row.id, "licensee", "deactivation", localShopId, deviceId, remoteAddress, new Date(this.now()).toISOString(), ""]
    );
    return { deactivated: true };
  }

  async submitManualPayment({ token, localShopId, deviceId, planId, amountMinor, currency, reference, note }, { remoteAddress } = {}) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }
    return await this.transaction(async (client) => {
      const row = await client.query(
        `SELECT licenses.*, shops.name AS shop_name FROM licenses
         JOIN shops ON shops.id = licenses.shop_id WHERE licenses.id = $1`,
        [payload.licenseId]
      );
      if (!row.rows[0]) throw new Error("The licensed shop was not found.");
      const licenseRow = row.rows[0];
      if (licenseRow.local_shop_id !== shopId || licenseRow.device_id !== device) {
        throw new Error("This license is no longer activated for this shop installation.");
      }
      if (licenseRow.state === "revoked" || licenseRow.state === "cancelled") {
        throw new Error(`Payment submission is unavailable while the license is ${licenseRow.state}. Contact the ShopPOS administrator.`);
      }
      const plan = this.plans.get(assertText(planId, "Plan ID", 40));
      if (!plan || !plan.available || plan.interval !== "monthly") {
        throw new Error("Choose an available monthly subscription plan.");
      }
      if (licenseRow.plan_id !== plan.id) {
        throw new Error("Payments cover this installation's own subscription plan.");
      }
      if (!Number.isSafeInteger(amountMinor) || amountMinor < 0) {
        throw new Error("Enter the payment amount as a non-negative integer of minor units.");
      }
      if (currency !== plan.currency) {
        throw new Error(`Payments for this plan must be recorded in ${plan.currency}.`);
      }
      if (amountMinor !== plan.priceMinor) {
        throw new Error("The submitted amount must exactly match the plan price. Partial amounts must be verified by the administrator.");
      }
      const normalizedReference = assertText(reference, "Payment reference", 120).trim();
      if (normalizedReference.length < 4) {
        throw new Error("The payment reference must be at least 4 characters.");
      }
      const now = new Date(this.now()).toISOString();
      const paymentId = crypto.randomUUID();
      await client.query(`
        INSERT INTO payments (
          id, shop_id, license_id, plan_id, method, status, amount_minor, currency,
          reference, reference_key, note, submitted_by_device, submitted_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, 'manual', 'pending', $5, $6, $7, $8, $9, $10, $11, $12, $13)
      `, [
        paymentId, licenseRow.shop_id, licenseRow.id, plan.id, amountMinor, currency,
        normalizedReference, `manual:${licenseRow.id}:${normalizedReference.toLowerCase()}`,
        note ? String(note).slice(0, 300) : null, device, now, now, now
      ]);
      await client.query(
        "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, 'submitted', 'licensee', $2, $3, $4)",
        [paymentId, remoteAddress ?? null, `reference:${normalizedReference}`, now]
      );
      const viewRow = await client.query(`
        SELECT payments.*, shops.name AS shop_name FROM payments
        JOIN shops ON shops.id = payments.shop_id WHERE payments.id = $1
      `, [paymentId]);
      if (!viewRow.rows[0]) throw new Error("Payment was not found.");
      return this.paymentViewRowFromDb(viewRow.rows[0]);
    });
  }

  async paymentView(id) {
    const row = await this.query(`
      SELECT payments.*, shops.name AS shop_name FROM payments
      JOIN shops ON shops.id = payments.shop_id WHERE payments.id = $1
    `, [id]);
    if (!row) throw new Error("Payment was not found.");
    return this.paymentViewRowFromDb(row);
  }

  async paymentViewRow(paymentId) {
    const row = await this.query(`
      SELECT payments.*, shops.name AS shop_name FROM payments
      JOIN shops ON shops.id = payments.shop_id WHERE payments.id = $1
    `, [paymentId]);
    if (!row) throw new Error("Payment was not found.");
    return this.paymentViewRowFromDb(row);
  }

  paymentViewRowFromDb(row) {
    return {
      id: row.id,
      shopId: row.shop_id,
      shopName: row.shop_name,
      licenseId: row.license_id,
      planId: row.plan_id,
      method: row.method,
      status: row.status,
      amountMinor: row.amount_minor,
      currency: row.currency,
      reference: row.reference,
      provider: row.provider ?? undefined,
      providerTransactionId: row.provider_transaction_id ?? undefined,
      note: row.note ?? undefined,
      decisionReason: row.decision_reason ?? undefined,
      submittedAt: row.submitted_at,
      decidedBy: row.decided_by ?? undefined,
      decidedAt: row.decided_at ?? undefined,
      appliedAt: row.applied_at ?? undefined
    };
  }

  async listPayments(statusFilter, limit = 500) {
    const safeStatus = statusFilter && PAYMENT_STATUSES.has(statusFilter) ? statusFilter : null;
    const rows = await this.all(`
      SELECT payments.*, shops.name AS shop_name FROM payments
      JOIN shops ON shops.id = payments.shop_id
      ${safeStatus ? "WHERE payments.status = $1" : ""}
      ORDER BY payments.submitted_at DESC LIMIT $2
    `, safeStatus ? [safeStatus, limit] : [limit]);
    return rows.map(row => this.listPaymentRow(row));
  }

  listPaymentRow(row) {
    return {
      id: row.id,
      shopId: row.shop_id,
      shopName: row.shop_name,
      licenseId: row.license_id,
      planId: row.plan_id,
      method: row.method,
      status: row.status,
      amountMinor: row.amount_minor,
      currency: row.currency,
      reference: row.reference,
      provider: row.provider ?? undefined,
      providerTransactionId: row.provider_transaction_id ?? undefined,
      submittedByDevice: row.submitted_by_device ?? undefined,
      submittedAt: row.submitted_at,
      decidedBy: row.decided_by ?? undefined,
      decidedAt: row.decided_at ?? undefined,
      appliedAt: row.applied_at ?? undefined,
      decisionReason: row.decision_reason ?? undefined
    };
  }

  async licenseePayments({ token, localShopId, deviceId, limit = 50 }) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }
    const { row } = await this.getLicense(payload.licenseId);
    if (row.local_shop_id !== shopId || row.device_id !== device) {
      throw new Error("This license is no longer activated for this shop installation.");
    }
    const boundedLimit = Math.min(Math.max(1, Number(limit) || 50), 100);
    const rows = await this.all(`
      SELECT id, plan_id, method, status, amount_minor, currency, reference,
        provider, provider_transaction_id, submitted_at, decided_at, decision_reason, applied_at
      FROM payments WHERE license_id = $1 ORDER BY submitted_at DESC LIMIT $2
    `, [row.id, boundedLimit]);
    return rows.map(item => ({
      id: item.id,
      planId: item.plan_id,
      method: item.method,
      status: item.status,
      amountMinor: item.amount_minor,
      currency: item.currency,
      reference: item.reference,
      provider: item.provider ?? undefined,
      providerTransactionId: item.provider_transaction_id ?? undefined,
      submittedAt: item.submitted_at,
      decidedAt: item.decided_at ?? undefined,
      appliedAt: item.applied_at ?? undefined,
      decisionReason: item.decision_reason ?? undefined
    }));
  }

  async approvePayment(paymentId, { actorId, remoteAddress } = {}) {
    const payment = await this.query("SELECT * FROM payments WHERE id = $1", [paymentId]);
    if (!payment) throw new Error("Payment was not found.");
    if (payment.status !== "pending") throw new Error("An already decided payment cannot be approved again.");
    const license = await this.getLicense(payment.license_id);
    if (!license) throw new Error("The payment's license was not found.");
    const plan = this.plans.get(payment.plan_id);
    if (!plan || !plan.available) throw new Error("The payment references a plan that is no longer available.");
    if (payment.currency !== plan.currency || payment.amount_minor !== plan.priceMinor) {
      throw new Error("The submitted amount or currency no longer matches the plan price. Reject it with a reason instead.");
    }
    const now = new Date(this.now()).toISOString();
    const result = await this.pool.query(
      "UPDATE payments SET status = 'approved', decided_by = $1, decided_at = $2, updated_at = $3 WHERE id = $4 AND status = 'pending'",
      [actorId ?? null, now, now, paymentId]
    );
    if (result.rowCount !== 1) throw new Error("An already decided payment cannot be approved again.");
    const view = await this.applyRenewal(payment.license_id, payment.plan_id, { actorId, paymentId });
    await this.pool.query("UPDATE payments SET applied_at = $1, updated_at = $2 WHERE id = $3",
      [now, now, paymentId]);
    await this.pool.query(
      "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, 'approved', $2, $3, $4, $5)",
      [paymentId, actorId ?? null, remoteAddress ?? null, `renewed_license:${payment.license_id}`, now]
    );
    return { payment: await this.paymentViewRow(paymentId), license: view };
  }

  async rejectPayment(paymentId, { actorId, reason, remoteAddress } = {}) {
    const rejectionReason = assertText(reason ?? "", "Rejection reason", 300).trim();
    if (rejectionReason.length < 3) {
      throw new Error("A rejection reason of at least 3 characters is required.");
    }
    try {
      return await this.transaction(async (client) => {
        const result = await client.query(
          "UPDATE payments SET status = 'rejected', decided_by = $1, decided_at = $2, decision_reason = $3, updated_at = $4 WHERE id = $5 AND status = 'pending'",
          [actorId ?? null, new Date(this.now()).toISOString(), rejectionReason, new Date(this.now()).toISOString(), paymentId]
        );
        if (result.rowCount !== 1) throw new Error("An already decided payment cannot be rejected again.");
        await client.query(
          "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, 'rejected', $2, $3, $4, $5)",
          [paymentId, actorId ?? null, remoteAddress ?? null, rejectionReason, new Date(this.now()).toISOString()]
        );
        const viewRow = await client.query(
          "SELECT payments.*, shops.name AS shop_name FROM payments JOIN shops ON shops.id = payments.shop_id WHERE payments.id = $1",
          [paymentId]
        );
        if (!viewRow.rows[0]) throw new Error("Payment was not found.");
        return this.paymentViewRowFromDb(viewRow.rows[0]);
      });
    } catch (error) {
      throw error;
    }
  }

  // Applies one verified gateway webhook event. Idempotent: repeat deliveries
  // with the same (provider, eventId) return without re-applying anything.
  async recordGatewayEvent(provider, normalized, { remoteAddress } = {}) {
    const now = new Date(this.now()).toISOString();
    try {
      await this.pool.query(
        `INSERT INTO gateway_events (provider, event_id, event_type, provider_transaction_id, remote_address, result, received_at)
         VALUES ($1, $2, $3, $4, $5, 'received', $6)`,
        [provider, normalized.eventId, normalized.eventType, normalized.transactionId, remoteAddress ?? null, now]
      );
    } catch (error) {
      if (/unique violation|duplicate key/i.test(error.message)) {
        return { duplicate: true, applied: false };
      }
      throw error;
    }
    const isSuccessful = normalized.status === "succeeded";
    const statusForEvent = isSuccessful ? "approved" : PAYMENT_STATUSES.has(normalized.status) ? normalized.status : null;
    let applied = false;
    let paymentId = null;
    if (!statusForEvent) {
      await this.pool.query(
        "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, 'gateway_unmatched', $2, $3, $4, $5)",
        [null, "gateway", remoteAddress ?? null, `${provider}:${normalized.eventId}:unknown status`, now]
      );
      await this.pool.query(
        "UPDATE gateway_events SET payment_id = $1, result = 'recorded' WHERE provider = $2 AND event_id = $3",
        [null, provider, normalized.eventId]
      );
      return { duplicate: false, applied: false };
    }
    const payment = await this.query(`
      SELECT * FROM payments
      WHERE lower(reference) = lower($1) AND status = 'pending'
      ORDER BY submitted_at DESC LIMIT 1
    `, [normalized.customerReference ?? ""]);
    if (payment) {
      paymentId = payment.id;
      if (isSuccessful) {
        if (normalized.amountMinor !== payment.amount_minor || normalized.currency !== payment.currency) {
          await this.pool.query(
            "INSERT INTO payment_events (payment_id, event, remote_address, detail, created_at) VALUES ($1, 'gateway_amount_mismatch', $2, $3, $4)",
            [paymentId, remoteAddress ?? null,
              `expected:${payment.currency}${payment.amount_minor} received:${normalized.currency}${normalized.amountMinor}`, now]
          );
        } else {
          const update = await this.pool.query(
            "UPDATE payments SET status = 'approved', method = 'gateway', provider = $1, provider_transaction_id = $2, decided_by = 'gateway', decided_at = $3, updated_at = $4 WHERE id = $5 AND status = 'pending'",
            [provider, normalized.transactionId, now, now, paymentId]
          );
          if (update.rowCount === 1) {
            const view = await this.applyRenewal(payment.license_id, payment.plan_id, { actorId: `gateway:${provider}`, paymentId });
            await this.pool.query("UPDATE payments SET applied_at = $1, updated_at = $2 WHERE id = $3", [now, now, paymentId]);
            await this.pool.query(
              "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, 'approved', 'gateway', $2, $3, $4)",
              [paymentId, remoteAddress ?? null, `renewed_license:${payment.license_id} term:${view.expiresAt}`, now]
            );
            applied = true;
          }
        }
      } else {
        await this.pool.query(
          "UPDATE payments SET status = $1, decided_by = 'gateway', decided_at = $2, updated_at = $3 WHERE id = $4 AND status = 'pending'",
          [statusForEvent, now, now, paymentId]
        );
        await this.pool.query(
          "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, $2, 'gateway', $3, $4, $5)",
          [paymentId, `gateway_${statusForEvent}`, remoteAddress ?? null, `${provider}:${normalized.eventId}`, now]
        );
      }
    } else {
      await this.pool.query(
        "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, 'gateway_unmatched', $2, $3, $4)",
        [null, "gateway", remoteAddress ?? null, `${provider}:${normalized.eventId}:${normalized.transactionId}`, now]
      );
    }
    await this.pool.query(
      "UPDATE gateway_events SET payment_id = $1, result = $2 WHERE provider = $3 AND event_id = $4",
      [paymentId, applied ? "applied" : "recorded", provider, normalized.eventId]
    );
    return { duplicate: false, applied };
  }

  async insertPaymentEvent(paymentId, event, { actorId = null, remoteAddress = null, detail = "" } = {}) {
    await this.pool.query(
      "INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
      [paymentId, event, actorId, remoteAddress, String(detail).slice(0, 300), new Date(this.now()).toISOString()]
    );
  }

  async subscriptionOverview() {
    const licenses = await this.list();
    return {
      licenses,
      counts: {
        total: licenses.length,
        active: licenses.filter(item => ["active", "trial"].includes(item.status)).length,
        gracePeriod: licenses.filter(item => item.status === "grace_period").length,
        expired: licenses.filter(item => item.status === "expired").length,
        suspended: licenses.filter(item => item.state === "suspended").length,
        cancelledOrRevoked: licenses.filter(item => ["cancelled", "revoked"].includes(item.state)).length
      }
    };
  }

  async recurringRevenue() {
    const periodStart = new Date(this.now());
    periodStart.setUTCDate(1);
    periodStart.setUTCHours(0, 0, 0, 0);
    // Monthly recurring revenue is reported from completed verified payments
    // only (approved payments applied this calendar month). Yearly plans are
    // normalized at one twelfth of their recorded amount.
    const rows = await this.all(`
      SELECT amount_minor, currency FROM payments
      WHERE status = 'approved' AND applied_at >= $1 AND applied_at < $2
    `, [periodStart.toISOString(), new Date(this.now()).toISOString()]);
    const totals = new Map();
    for (const row of rows) {
      const monthlyEquivalent = row.amount_minor;
      totals.set(row.currency, (totals.get(row.currency) ?? 0) + monthlyEquivalent);
    }
    return { period: { start: periodStart.toISOString() }, currencies: Object.fromEntries(totals) };
  }

  async paymentLogs(limit = 200) {
    return this.all(`
      SELECT id, payment_id AS paymentId, event, actor_id AS actorId, remote_address AS remoteAddress,
        detail, created_at AS createdAt FROM payment_events ORDER BY id DESC LIMIT $1
    `, [limit]);
  }

  async list() {
    const rows = await this.all(`
      SELECT licenses.*, shops.name AS shop_name FROM licenses
      JOIN shops ON shops.id = licenses.shop_id ORDER BY licenses.created_at DESC
    `);
    return rows.map(row => this.licenseView(row, this.plans.get(row.plan_id), this.now()));
  }

  async view(licenseId) {
    const { row, plan } = await this.getLicense(licenseId);
    return this.licenseView(row, plan, this.now());
  }

  async logs(licenseId) {
    return this.all(`
      SELECT id, license_id AS licenseId, actor_id AS actorId, event, local_shop_id AS localShopId, device_id AS deviceId,
        remote_address AS remoteAddress, created_at AS createdAt, detail
      FROM license_logs ${licenseId ? "WHERE license_id = $1" : ""} ORDER BY id DESC LIMIT 500
    `, licenseId ? [licenseId] : []);
  }

  async changeState(licenseId, state, { actorId } = {}) {
    const { row } = await this.getLicense(licenseId);
    if (row.state === "revoked" || (row.state === "cancelled" && state !== "revoked")) {
      throw new Error("A cancelled or revoked license cannot be reactivated.");
    }
    if (state === "reactivated" && row.state !== "suspended") throw new Error("Only a suspended license can be reactivated.");
    const nextState = state === "reactivated" ? "active" : state;
    const now = new Date(this.now()).toISOString();
    await this.pool.query("UPDATE licenses SET state = $1, updated_at = $2 WHERE id = $3", [nextState, now, row.id]);
    await this.pool.query(
      "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [row.id, actorId, state, null, null, null, now, ""]
    );
    return this.view(row.id);
  }

  async createBackup(backupDirectory) {
    if (!backupDirectory || typeof backupDirectory !== "string") {
      throw new Error("A backup directory path is required.");
    }
    if (this.closed) throw new Error("The license database is closed. Reopen the service before creating backups.");
    await this.schemaReady();
    fs.mkdirSync(backupDirectory, { recursive: true });
    const timestamp = new Date(this.now()).toISOString().replace(/[:\-]/g, "").split(".")[0] + "Z";
    const backupPath = path.join(backupDirectory, `shoppos-license-backup-${timestamp}-${crypto.randomUUID()}.sql`);
    const statements = [];
    const tableOrder = ["schema_meta", "shops", "plans", "licenses", "license_logs", "payments", "payment_events", "gateway_events"];
    for (const table of tableOrder) {
      try {
        // Emit the table definition so empty tables are still represented in
        // the backup (not only tables that happen to contain rows).
        const columns = await this.all(
          `SELECT column_name, data_type FROM information_schema.columns WHERE table_name = $1 ORDER BY ordinal_position`,
          [table]
        );
        if (columns.length > 0) {
          const colDefs = columns.map((col) => `"${col.column_name}" ${col.data_type}`).join(", ");
          statements.push(`CREATE TABLE IF NOT EXISTS ${table} (${colDefs});`);
        }
        const rows = await this.all(`SELECT * FROM ${table}`);
        for (const row of rows) {
          const columnNames = Object.keys(row);
          const values = columnNames.map((col) => this.sqlLiteral(row[col]));
          statements.push(`INSERT INTO ${table} (${columnNames.join(", ")}) VALUES (${values.join(", ")});`);
        }
      } catch {
        // Table may not exist yet in an uninitialized schema; skip.
      }
    }
    const temporary = `${backupPath}.tmp`;
    fs.writeFileSync(temporary, statements.join("\n") + "\n", { flag: "wx", mode: 0o600 });
    fs.renameSync(temporary, backupPath);
    return { backupPath, backupFile: path.basename(backupPath), createdAt: new Date(this.now()).toISOString() };
  }

  sqlLiteral(value) {
    if (value === null || value === undefined) return "NULL";
    if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
    if (typeof value === "number") return Number.isFinite(value) ? String(value) : "NULL";
    if (value instanceof Date) return `'${value.toISOString()}'`;
    const text = String(value).replace(/'/g, "''");
    return `'${text}'`;
  }

  async verifyBackup(backupPath) {
    if (!fs.existsSync(backupPath)) throw new Error("Backup file was not found.");
    const text = fs.readFileSync(backupPath, "utf8");
    const required = ["shops", "licenses", "license_logs", "plans", "payments", "payment_events", "gateway_events"];
    const missing = required.filter(
      (name) =>
        !text.includes(`INTO ${name}`) &&
        !text.includes(`CREATE TABLE IF NOT EXISTS ${name}`) &&
        !text.includes(`CREATE TABLE ${name}`)
    );
    if (missing.length > 0) throw new Error(`Backup verification failed: missing tables ${missing.join(", ")}.`);
    const versionMatch =
      text.match(/INSERT INTO schema_meta[^;]*?VALUES\s*\(\s*1\s*,\s*(\d+)\s*\)/i) ??
      text.match(/schema_meta[^;]*?version\s*=\s*(\d+)/i);
    const version = versionMatch ? Number(versionMatch[1]) : 0;
    if (version !== SCHEMA_VERSION) {
      throw new Error(`Backup verification failed: incompatible schema version ${version}.`);
    }
    return { valid: true, schemaVersion: version, verifiedAt: new Date(this.now()).toISOString() };
  }

  async restoreFromBackup(backupPath, { actorId } = {}) {
    if (!fs.existsSync(backupPath)) throw new Error("Backup file was not found.");
    const verification = await this.verifyBackup(backupPath);
    if (!verification.valid || verification.schemaVersion !== SCHEMA_VERSION) {
      throw new Error("Backup verification failed or its schema is incompatible.");
    }
    const preRestoreBackup = await this.createBackup(path.dirname(backupPath));
    const safetyVerification = await this.verifyBackup(preRestoreBackup.backupPath);
    if (!safetyVerification.valid || safetyVerification.schemaVersion !== SCHEMA_VERSION) {
      throw new Error("The pre-restore backup is invalid or incompatible.");
    }
    const text = fs.readFileSync(backupPath, "utf8");
    const statements = text.split(/\r?\n/).map(line => line.trim()).filter(line => line.length > 0 && !line.startsWith("--"));
    try {
      await this.transaction(async (client) => {
        for (const statement of statements) {
          await client.query(statement);
        }
      });
      this.plans = await this.loadPlans();
      await this.pool.query(
        "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        [null, actorId, "database_restored", null, null, null, new Date(this.now()).toISOString(), `restored_from:${path.basename(backupPath)}`]
      );
      return { restored: true, fromBackup: path.basename(backupPath), preRestoreBackup: preRestoreBackup.backupFile, restoredAt: new Date(this.now()).toISOString() };
    } catch (error) {
      throw error;
    }
  }

  async close() {
    if (this.closed) return;
    await this.pool.end();
    this.closed = true;
  }
}

async function initializePostgresService(options = {}) {
  const service = new PostgresLicenseService({
    databaseUrl: options.databaseUrl ?? process.env.POSTGRES_DATABASE_URL,
    plans: options.plans ?? process.env.LICENSE_PLANS_JSON,
    privateKey: options.privateKey ?? process.env.LICENSE_SIGNING_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    offlineGraceDays: options.offlineGraceDays ?? Number(process.env.LICENSE_OFFLINE_GRACE_DAYS ?? 7),
    now: options.now,
    max: options.max
  });
  await service.ensureSchema();
  return service;
}

async function createPostgresLicenseServer(options = {}) {
  const { createLicenseServer } = require("./license-server.cjs");
  const service = new PostgresLicenseService({
    databaseUrl: options.databaseUrl ?? process.env.POSTGRES_DATABASE_URL,
    plans: options.plans ?? process.env.LICENSE_PLANS_JSON,
    privateKey: options.privateKey ?? process.env.LICENSE_SIGNING_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    offlineGraceDays: options.offlineGraceDays ?? Number(process.env.LICENSE_OFFLINE_GRACE_DAYS ?? 7),
    now: options.now,
    max: options.max
  });
  await service.ensureSchema();
  const instance = createLicenseServer({
    service,
    admins: options.admins ?? process.env.LICENSE_ADMIN_USERS_JSON,
    host: options.host ?? process.env.LICENSE_HOST ?? "127.0.0.1",
    port: options.port ?? Number(process.env.LICENSE_PORT ?? process.env.PORT ?? 8787),
    secureCookies: options.secureCookies ?? process.env.NODE_ENV === "production",
    trustProxy: options.trustProxy ?? process.env.LICENSE_TRUST_PROXY
  });
  return { ...instance, service };
}

module.exports = {
  PostgresLicenseService,
  createPostgresLicenseServer,
  initializePostgresService,
  loadMigrations,
  SCHEMA_VERSION,
  addPeriod,
  statusFor,
  parsePlans,
  parseAdminUsers,
  validateServerConfiguration,
  validatePostgresServerConfiguration
};
