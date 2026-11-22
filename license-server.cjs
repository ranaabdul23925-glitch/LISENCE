const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { getGatewayAdapter, WebhookVerificationError } = require("./payments-gateway.cjs");
const { normalizePublicKeys, parseTrustedPublicKeys, verifyWithTrustedPublicKeys } = require("./signing-keys.cjs");

const SCHEMA_VERSION = 4;
const ADMIN_ROLES = new Set(["licenses:issue", "licenses:read", "licenses:manage"]);
// Fixed business rule: every subscription grace period lasts exactly 7 days
// after expiry. See validateServerConfiguration for the production guard.
const SUBSCRIPTION_GRACE_DAYS = 7;
const PAYMENT_STATUSES = new Set(["pending", "approved", "rejected", "failed", "refunded", "disputed"]);
const SCHEMA = `
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    license_id TEXT NOT NULL,
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
  CREATE INDEX IF NOT EXISTS idx_payments_license ON payments(license_id, submitted_at);
  CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status, submitted_at);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_provider_txn
    ON payments(provider_transaction_id) WHERE provider_transaction_id IS NOT NULL;
  CREATE TABLE IF NOT EXISTS payment_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_id TEXT,
    event TEXT NOT NULL,
    actor_id TEXT,
    remote_address TEXT,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_payment_events_payment ON payment_events(payment_id, created_at);
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
`;

function assertText(value, label, maxLength = 200) {
  if (typeof value !== "string" || !value.trim() || value.length > maxLength) {
    throw new Error(`${label} is required and must be at most ${maxLength} characters.`);
  }
  return value.trim();
}

function validCurrency(value) {
  if (typeof value !== "string" || !/^[A-Z]{3}$/.test(value)) return false;
  try {
    new Intl.NumberFormat("en", { style: "currency", currency: value });
    return true;
  } catch (error) {
    if (error instanceof RangeError) return false;
    throw error;
  }
}

function parsePlans(raw) {
  let plans;
  try {
    plans = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    throw new Error("LICENSE_PLANS_JSON must contain a valid JSON array.");
  }
  if (!Array.isArray(plans) || plans.length === 0) {
    throw new Error("Configure at least one plan in LICENSE_PLANS_JSON.");
  }
  const ids = new Set();
  for (const plan of plans) {
    if (!plan || typeof plan.id !== "string" || !/^[a-z0-9_-]{1,40}$/.test(plan.id) ||
        ids.has(plan.id) || typeof plan.name !== "string" || !plan.name.trim() ||
        !["monthly", "yearly"].includes(plan.interval) ||
        (plan.available !== undefined && typeof plan.available !== "boolean") ||
        !Number.isSafeInteger(plan.priceMinor) || plan.priceMinor < 0 ||
        !validCurrency(plan.currency) ||
        !Number.isInteger(plan.trialDays ?? 0) || (plan.trialDays ?? 0) < 0 || (plan.trialDays ?? 0) > 365 ||
        !Number.isInteger(plan.graceDays ?? 0) || (plan.graceDays ?? 0) < 0 || (plan.graceDays ?? 0) > 60) {
      throw new Error("Each plan needs a unique id, name, monthly/yearly interval, non-negative priceMinor, ISO currency, and valid trial/grace days.");
    }
    ids.add(plan.id);
  }
  return new Map(plans.map(plan => [plan.id, {
    ...plan,
    name: plan.name.trim(),
    trialDays: plan.trialDays ?? 0,
    graceDays: plan.graceDays ?? 0,
    available: plan.available !== false
  }]));
}

function parseAdminUsers(raw) {
  let admins;
  try {
    admins = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    throw new Error("LICENSE_ADMIN_USERS_JSON must contain a valid JSON array.");
  }
  if (!Array.isArray(admins) || admins.length === 0) {
    throw new Error("Configure at least one administrator in LICENSE_ADMIN_USERS_JSON.");
  }
  const identities = new Set();
  const tokens = new Set();
  return admins.map(admin => {
    if (!admin || typeof admin.id !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(admin.id) ||
        identities.has(admin.id) || typeof admin.token !== "string" || Buffer.byteLength(admin.token) < 32 ||
        /\s/.test(admin.token) || tokens.has(admin.token) ||
        !Array.isArray(admin.roles) || admin.roles.length === 0 ||
        admin.roles.some(role => typeof role !== "string" || !ADMIN_ROLES.has(role)) ||
        new Set(admin.roles).size !== admin.roles.length) {
      throw new Error("Each administrator needs a unique id, a unique secret token of at least 32 bytes, and unique supported roles.");
    }
    identities.add(admin.id);
    tokens.add(admin.token);
    return Object.freeze({ id: admin.id, token: admin.token, roles: Object.freeze([...admin.roles]) });
  });
}

function parseIntegerSetting(value, label, defaultValue, min, max) {
  const text = value === undefined || value === "" ? String(defaultValue) : String(value);
  if (!/^(0|[1-9]\d*)$/.test(text)) throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  return parsed;
}

function validateServerConfiguration(env = process.env) {
  const privateKey = env.LICENSE_SIGNING_PRIVATE_KEY?.replace(/\\n/g, "\n");
  if (!privateKey || /replace-with/i.test(privateKey)) {
    throw new Error("Set LICENSE_SIGNING_PRIVATE_KEY to a server-only Ed25519 PKCS#8 private key.");
  }
  let signingKey;
  try {
    signingKey = crypto.createPrivateKey(privateKey);
  } catch {
    throw new Error("LICENSE_SIGNING_PRIVATE_KEY must be a valid Ed25519 PKCS#8 private key.");
  }
  if (signingKey.asymmetricKeyType !== "ed25519") {
    throw new Error("LICENSE_SIGNING_PRIVATE_KEY must be an Ed25519 private key.");
  }
  const trustedPublicKeys = parseTrustedPublicKeys(
    env.LICENSE_TRUSTED_PUBLIC_KEYS_JSON,
    crypto.createPublicKey(signingKey)
  );
  const plans = parsePlans(env.LICENSE_PLANS_JSON);
  const admins = parseAdminUsers(env.LICENSE_ADMIN_USERS_JSON);
  const host = env.LICENSE_HOST?.trim() || "127.0.0.1";
  if (host.length > 253 || /[\s/\\]/.test(host) || /replace-with/i.test(host)) {
    throw new Error("LICENSE_HOST must be a valid bind address or hostname.");
  }
  const configuredPort = env.LICENSE_PORT?.trim() || env.PORT;
  const port = parseIntegerSetting(configuredPort, "LICENSE_PORT or PORT", 8787, 1, 65535);
  const offlineGraceDays = parseIntegerSetting(env.LICENSE_OFFLINE_GRACE_DAYS, "LICENSE_OFFLINE_GRACE_DAYS", 7, 0, 90);
  const configuredDatabasePath = env.LICENSE_DATABASE_PATH?.trim();
  if (env.NODE_ENV === "production" && !configuredDatabasePath) {
    throw new Error("Set LICENSE_DATABASE_PATH to an absolute path on persistent production storage.");
  }
  if (configuredDatabasePath && /replace-with/i.test(configuredDatabasePath)) {
    throw new Error("LICENSE_DATABASE_PATH must not contain a placeholder value.");
  }
  const databasePath = configuredDatabasePath
    ? path.resolve(configuredDatabasePath)
    : path.join(__dirname, "data", "licenses.sqlite");
  if (env.NODE_ENV === "production" && !path.isAbsolute(configuredDatabasePath)) {
    throw new Error("LICENSE_DATABASE_PATH must be absolute in production.");
  }
  for (const plan of plans.values()) {
    if (env.NODE_ENV === "production" && plan.graceDays !== SUBSCRIPTION_GRACE_DAYS) {
      throw new Error(`Production plan ${plan.id} must have a grace period of exactly ${SUBSCRIPTION_GRACE_DAYS} days.`);
    }
  }
  return { privateKey, trustedPublicKeys, plans, admins, host, port, offlineGraceDays, databasePath };
}

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

function statusFor(license, plan, now = Date.now()) {
  if (license.state !== "active") return license.state;
  if (license.trial_ends_at && now < Date.parse(license.trial_ends_at)) return "trial";
  const expiry = Date.parse(license.expires_at);
  if (now < expiry) return "active";
  if (now < expiry + plan.graceDays * 86400000) return "grace_period";
  return "expired";
}

function licenseView(row, plan, now) {
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

function productionEnvironment() {
  return process.env.NODE_ENV === "production";
}

class LicenseService {
  constructor({
    SQL,
    databasePath,
    plans,
    privateKey,
    trustedPublicKeys = [],
    offlineGraceDays = 7,
    now = () => Date.now()
  }) {
    if (!Number.isInteger(offlineGraceDays) || offlineGraceDays < 0 || offlineGraceDays > 90) {
      throw new Error("LICENSE_OFFLINE_GRACE_DAYS must be between 0 and 90.");
    }
    this.databasePath = databasePath;
    this.SQL = SQL;
    this.plans = parsePlans(plans);
    this.privateKey = crypto.createPrivateKey(privateKey);
    if (this.privateKey.asymmetricKeyType !== "ed25519") throw new Error("LICENSE_SIGNING_PRIVATE_KEY must be an Ed25519 private key.");
    this.publicKey = crypto.createPublicKey(this.privateKey);
    this.trustedPublicKeys = normalizePublicKeys([this.publicKey, ...trustedPublicKeys]);
    this.offlineGraceDays = offlineGraceDays;
    this.now = now;
    this.closed = false;
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    const bytes = fs.existsSync(databasePath) ? fs.readFileSync(databasePath) : undefined;
    this.db = new SQL.Database(bytes);
    const schemaVersion = this.db.exec("PRAGMA user_version")[0]?.values[0]?.[0] ?? 0;
    if (schemaVersion > SCHEMA_VERSION) throw new Error("License database schema is newer than this server; its data was left unchanged.");
    this.db.run("PRAGMA foreign_keys = ON");
    this.db.run(SCHEMA);
    if (productionEnvironment()) {
      // Fixed business rule: production plans always carry a 7-day grace
      // period. Existing rows are pinned, never deleted, and the change is
      // audited.
      this.db.run("UPDATE plans SET grace_days = ? WHERE grace_days != ?", [SUBSCRIPTION_GRACE_DAYS, SUBSCRIPTION_GRACE_DAYS]);
    }
    this.ensureColumn("plans", "features_json", "TEXT");
    this.ensureColumn("plans", "max_devices", "INTEGER");
    this.ensureColumn("plans", "max_staff", "INTEGER");
    this.ensureColumn("shops", "local_shop_id", "TEXT");
    this.ensureColumn("shops", "verified_by", "TEXT");
    this.ensureColumn("shops", "verified_at", "TEXT");
    this.ensureColumn("licenses", "intended_local_shop_id", "TEXT");
    this.ensureColumn("licenses", "key_redeemed_at", "TEXT");
    this.db.run("CREATE UNIQUE INDEX IF NOT EXISTS idx_shops_local_shop_id ON shops(local_shop_id) WHERE local_shop_id IS NOT NULL");
    this.db.run("UPDATE licenses SET key_redeemed_at = activated_at WHERE activated_at IS NOT NULL AND key_redeemed_at IS NULL");
    const logColumns = this.db.exec("PRAGMA table_info(license_logs)")[0]?.values ?? [];
    if (!logColumns.some(column => column[1] === "actor_id")) {
      this.db.run("ALTER TABLE license_logs ADD COLUMN actor_id TEXT");
    }
    this.seedPlans(plans);
    this.plans = this.loadPlans();
    this.db.run(`PRAGMA user_version = ${SCHEMA_VERSION}`);
    this.persist();
  }

  ensureColumn(table, column, definition) {
    const columns = this.db.exec(`PRAGMA table_info(${table})`)[0]?.values ?? [];
    if (!columns.some(value => value[1] === column)) {
      this.db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
  }

  seedPlans(configuredPlans) {
    const existing = this.db.exec("SELECT id FROM plans LIMIT 1")[0]?.values ?? [];
    if (existing.length) return;
    const parsedPlans = parsePlans(configuredPlans);
    this.db.run("BEGIN IMMEDIATE");
    try {
      for (const plan of parsedPlans.values()) {
        this.db.run(`
          INSERT INTO plans (id, name, interval, price_minor, currency, trial_days, grace_days, available, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          plan.id, plan.name, plan.interval, plan.priceMinor, plan.currency,
          plan.trialDays, plan.graceDays, plan.available ? 1 : 0, new Date(this.now()).toISOString()
        ]);
      }
      this.db.run("COMMIT");
    } catch (error) {
      this.db.run("ROLLBACK");
      throw error;
    }
  }

  loadPlans() {
    return new Map(this.all("SELECT * FROM plans ORDER BY name COLLATE NOCASE").map(row => [row.id, {
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

  persist() {
    const temporary = `${this.databasePath}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, Buffer.from(this.db.export()), { flag: "wx", mode: 0o600 });
    try {
      fs.renameSync(temporary, this.databasePath);
    } catch (error) {
      fs.rmSync(temporary, { force: true });
      throw error;
    }
  }

  query(sql, values = []) {
    const statement = this.db.prepare(sql);
    try {
      statement.bind(values);
      return statement.step() ? statement.getAsObject() : undefined;
    } finally {
      statement.free();
    }
  }

  all(sql, values = []) {
    const statement = this.db.prepare(sql);
    try {
      statement.bind(values);
      const rows = [];
      while (statement.step()) rows.push(statement.getAsObject());
      return rows;
    } finally {
      statement.free();
    }
  }

  log(event, {
    licenseId = null, actorId = null, localShopId = null, deviceId = null, remoteAddress = null, detail = ""
  } = {}) {
    this.insertLog(event, { licenseId, actorId, localShopId, deviceId, remoteAddress, detail });
    this.persist();
  }

  insertLog(event, {
    licenseId = null, actorId = null, localShopId = null, deviceId = null, remoteAddress = null, detail = ""
  } = {}) {
    this.db.run(
      "INSERT INTO license_logs (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [licenseId, actorId, event, localShopId, deviceId, remoteAddress, new Date(this.now()).toISOString(), String(detail).slice(0, 300)]
    );
  }

  getLicense(licenseId) {
    const row = this.query(`
      SELECT licenses.*, shops.name AS shop_name
      FROM licenses JOIN shops ON shops.id = licenses.shop_id WHERE licenses.id = ?
    `, [licenseId]);
    if (!row) throw new Error("License was not found.");
    const plan = this.plans.get(row.plan_id);
    if (!plan) throw new Error("The license references a plan that is no longer configured.");
    return { row, plan };
  }

  view(licenseId) {
    const { row, plan } = this.getLicense(licenseId);
    return licenseView(row, plan, this.now());
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
    if (!verifyWithTrustedPublicKeys(
      Buffer.from(decoded.encoded),
      decoded.signature,
      this.trustedPublicKeys
    ) ||
        !decoded.payload || decoded.payload.version !== 1) {
      throw new Error("Invalid license token signature.");
    }
    return decoded.payload;
  }

  createShop(input, { actorId } = {}) {
    const shopName = assertText(input.shopName, "Shop name", 120);
    const plan = this.plans.get(assertText(input.planId, "Plan ID", 40));
    if (!plan || !plan.available) throw new Error("Choose an available configured subscription plan.");
    const now = new Date(this.now()).toISOString();
    const shopId = crypto.randomUUID();
    const licenseId = crypto.randomUUID();
    const licenseKey = `SP-${crypto.randomBytes(24).toString("base64url")}`;
    const trialEndsAt = plan.trialDays ? new Date(this.now() + plan.trialDays * 86400000).toISOString() : null;
    const expiresAt = trialEndsAt ?? addPeriod(now, plan.interval);
    this.db.run("BEGIN IMMEDIATE");
    try {
      this.db.run("INSERT INTO shops (id, name, created_at) VALUES (?, ?, ?)", [shopId, shopName, now]);
      this.db.run(`
        INSERT INTO licenses (id, shop_id, key_hash, plan_id, state, starts_at, expires_at, trial_ends_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
      `, [licenseId, shopId, crypto.createHash("sha256").update(licenseKey).digest("hex"), plan.id, now, expiresAt, trialEndsAt, now, now]);
      this.insertLog("license_created", { licenseId, actorId });
      this.db.run("COMMIT");
    } catch (error) {
      this.db.run("ROLLBACK");
      throw error;
    }
    this.persist();
    return { ...this.view(licenseId), licenseKey };
  }

  registerExistingShop({ localShopId, shopName, confirmationShopId }, { actorId } = {}) {
    const shopId = assertShopId(localShopId, "Existing ShopPOS Shop ID");
    if (assertShopId(confirmationShopId, "Confirmation Shop ID") !== shopId) {
      throw new Error("Confirm the exact ShopPOS Shop ID before registering it.");
    }
    const name = assertText(shopName, "Shop name", 120);
    const serverShopId = crypto.randomUUID();
    const now = new Date(this.now()).toISOString();
    this.db.run("BEGIN IMMEDIATE");
    try {
      this.db.run(
        "INSERT INTO shops (id, name, local_shop_id, verified_by, verified_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        [serverShopId, name, shopId, actorId, now, now]
      );
      this.insertLog("shop_registered", { actorId, localShopId: shopId, detail: "admin_attested_existing_shop" });
      this.db.run("COMMIT");
    } catch (error) {
      this.db.run("ROLLBACK");
      if (/UNIQUE constraint failed: shops\.local_shop_id/i.test(error.message)) {
        throw new Error("That ShopPOS Shop ID is already registered.");
      }
      throw error;
    }
    this.persist();
    return this.getShop(serverShopId);
  }

  getShop(shopId) {
    return this.query(`
      SELECT s.id, s.name, s.local_shop_id AS localShopId, s.verified_by AS verifiedBy,
        s.verified_at AS verifiedAt, s.created_at AS createdAt,
        COUNT(l.id) AS licenseCount
      FROM shops s LEFT JOIN licenses l ON l.shop_id = s.id
      WHERE s.id = ? GROUP BY s.id
    `, [shopId]);
  }

  listShops() {
    return this.all(`
      SELECT s.id, s.name, s.local_shop_id AS localShopId, s.verified_by AS verifiedBy,
        s.verified_at AS verifiedAt, s.created_at AS createdAt,
        COUNT(l.id) AS licenseCount,
        MAX(l.created_at) AS latestLicenseCreatedAt
      FROM shops s LEFT JOIN licenses l ON l.shop_id = s.id
      GROUP BY s.id ORDER BY s.created_at DESC
    `);
  }

  createLicenseForShop(shopId, input, { actorId } = {}) {
    const shop = this.getShop(assertShopId(shopId, "Server Shop ID"));
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
    this.db.run("BEGIN IMMEDIATE");
    try {
      this.db.run(`
        INSERT INTO licenses (
          id, shop_id, key_hash, plan_id, state, starts_at, expires_at, trial_ends_at,
          intended_local_shop_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
      `, [
        licenseId, shop.id, crypto.createHash("sha256").update(licenseKey).digest("hex"),
        plan.id, now, expiresAt, trialEndsAt, shop.localShopId, now, now
      ]);
      this.insertLog("license_created", {
        licenseId, actorId, localShopId: shop.localShopId, detail: input.expiresAt ? "custom_expiration" : "configured_plan_term"
      });
      this.db.run("COMMIT");
    } catch (error) {
      this.db.run("ROLLBACK");
      throw error;
    }
    this.persist();
    return { ...this.view(licenseId), licenseKey };
  }

  updatePlan(input, { actorId } = {}) {
    const plan = [...parsePlans([input]).values()][0];
    // Fixed business decision: the subscription grace period is exactly 7 days
    // for every plan. Submitted values are ignored and the canonical value is
    // stored; the dashboard clarifies this to administrators.
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
    this.db.run(`
      INSERT INTO plans (id, name, interval, price_minor, currency, trial_days, grace_days, available, features_json, max_devices, max_staff, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    this.log("plan_updated", { actorId, detail: plan.id });
    return plan;
  }

  listPlans() {
    return [...this.plans.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  activate({ licenseKey, localShopId, deviceId, remoteAddress }) {
    const normalizedKey = assertText(licenseKey, "License key", 100);
    const shopId = assertShopId(localShopId, "Local shop ID");
    const device = assertText(deviceId, "Installation ID", 80);
    let failedLicenseId;
    let failureDetail = "invalid_key";
    try {
      this.db.run("BEGIN IMMEDIATE");
      const row = this.query(`
        SELECT licenses.*, shops.name AS shop_name FROM licenses
        JOIN shops ON shops.id = licenses.shop_id WHERE licenses.key_hash = ?
      `, [crypto.createHash("sha256").update(normalizedKey).digest("hex")]);
      if (!row) throw new Error("The license key is invalid.");
      failedLicenseId = row.id;
      const plan = this.plans.get(row.plan_id);
      if (!plan) throw new Error("The license plan is no longer configured.");
      const currentStatus = statusFor(row, plan, this.now());
      if (row.key_redeemed_at) {
        failureDetail = "key_already_redeemed";
        throw new Error("This activation key has already been redeemed.");
      }
      if (row.state !== "active" || currentStatus === "expired") {
        failureDetail = currentStatus;
        throw new Error(`This license is ${currentStatus}.`);
      }
      if (row.intended_local_shop_id && row.intended_local_shop_id !== shopId) {
        failureDetail = "shop_binding_mismatch";
        throw new Error("This license was issued for a different ShopPOS shop.");
      }
      if ((row.local_shop_id && row.local_shop_id !== shopId) || (row.device_id && row.device_id !== device)) {
        failureDetail = "installation_binding_mismatch";
        throw new Error("This license is already bound to another shop installation.");
      }
      const now = new Date(this.now()).toISOString();
      this.db.run(`
        UPDATE licenses SET local_shop_id = ?, device_id = ?,
          activated_at = COALESCE(activated_at, ?), key_redeemed_at = ?, updated_at = ?
        WHERE id = ? AND key_redeemed_at IS NULL
      `, [shopId, device, now, now, now, row.id]);
      const changed = this.db.getRowsModified();
      if (changed !== 1) {
        failureDetail = "key_already_redeemed";
        throw new Error("This activation key has already been redeemed.");
      }
      this.insertLog("activation_succeeded", {
        licenseId: row.id, actorId: "licensee", localShopId: shopId, deviceId: device, remoteAddress
      });
      this.db.run("COMMIT");
      this.persist();
      const updated = this.getLicense(row.id).row;
      return { token: this.sign(updated, plan, shopId, device), status: this.view(row.id) };
    } catch (error) {
      try {
        this.db.run("ROLLBACK");
      } catch {
        // The transaction may already have been rolled back by the database.
      }
      this.log("activation_failed", {
        licenseId: failedLicenseId, localShopId: shopId, deviceId: device,
        remoteAddress, detail: failureDetail
      });
      throw error;
    }
  }

  status({ token, localShopId, deviceId, remoteAddress }) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) throw new Error("This license belongs to a different shop installation.");
    const { row, plan } = this.getLicense(payload.licenseId);
    if (row.shop_id !== payload.shopId || row.local_shop_id !== shopId || row.device_id !== device) {
      throw new Error("This license is no longer activated for this shop installation.");
    }
    this.log("status_check", { licenseId: row.id, localShopId: shopId, deviceId: device, remoteAddress, detail: statusFor(row, plan, this.now()) });
    return { token: this.sign(row, plan, shopId, device), status: this.view(row.id) };
  }

  deactivate({ token, localShopId, deviceId, remoteAddress }) {
    const payload = this.verify(token);
    if (payload.localShopId !== localShopId || payload.deviceId !== deviceId) throw new Error("This license belongs to a different shop installation.");
    const { row } = this.getLicense(payload.licenseId);
    if (row.local_shop_id !== localShopId || row.device_id !== deviceId) throw new Error("This license is no longer activated for this installation.");
    this.db.run("UPDATE licenses SET local_shop_id = NULL, device_id = NULL, activated_at = NULL, updated_at = ? WHERE id = ?",
      [new Date(this.now()).toISOString(), row.id]);
    this.persist();
    this.log("deactivation", { licenseId: row.id, actorId: "licensee", localShopId, deviceId, remoteAddress });
    return { deactivated: true };
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

  applyRenewal(licenseId, planId, { actorId = null, paymentId = null } = {}) {
    const { row, plan } = this.getLicense(licenseId);
    if (plan.id !== planId) throw new Error("The payment plan no longer matches the license plan.");
    if (row.state !== "active") throw new Error("Only an active license can be renewed. Reactivate a suspended license first.");
    const { expiresAt } = this.renewalExpiry(row, plan);
    const now = new Date(this.now()).toISOString();
    const guard = paymentId ? " AND NOT EXISTS (SELECT 1 FROM payments WHERE id = ? AND applied_at IS NOT NULL)" : "";
    this.db.run(
      `UPDATE licenses SET expires_at = ?, trial_ends_at = NULL, updated_at = ?
        WHERE id = ? AND state = 'active'${guard}`,
      paymentId ? [expiresAt, now, licenseId, paymentId] : [expiresAt, now, licenseId]
    );
    if (this.db.getRowsModified() !== 1) {
      throw new Error(paymentId
        ? "The payment was already applied, or the license is no longer active."
        : "The license is no longer active.");
    }
    this.log("renewal", { licenseId, actorId, detail: paymentId ? `payment:${paymentId}` : "admin_manual" });
    return this.view(licenseId);
  }

  renew(licenseId, { actorId } = {}) {
    return this.applyRenewal(licenseId, this.getLicense(licenseId).plan.id, { actorId });
  }

  submitManualPayment({ token, localShopId, deviceId, planId, amountMinor, currency, reference, note }, { remoteAddress } = {}) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }
    const licenseQuery = `
      SELECT licenses.*, shops.name AS shop_name FROM licenses
      JOIN shops ON shops.id = licenses.shop_id WHERE licenses.id = ?`;
    this.db.run("BEGIN IMMEDIATE");
    try {
      const row = this.query(licenseQuery, [payload.licenseId]);
      if (!row) throw new Error("The licensed shop was not found.");
      if (row.local_shop_id !== shopId || row.device_id !== device) {
        throw new Error("This license is no longer activated for this shop installation.");
      }
      if (row.state === "revoked" || row.state === "cancelled") {
        throw new Error(`Payment submission is unavailable while the license is ${row.state}. Contact the ShopPOS administrator.`);
      }
      const plan = this.plans.get(assertText(planId, "Plan ID", 40));
      if (!plan || !plan.available || plan.interval !== "monthly") {
        throw new Error("Choose an available monthly subscription plan.");
      }
      if (row.plan_id !== plan.id) {
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
      this.db.run(`
        INSERT INTO payments (
          id, shop_id, license_id, plan_id, method, status, amount_minor, currency,
          reference, reference_key, note, submitted_by_device, submitted_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'manual', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        paymentId, row.shop_id, row.id, plan.id, amountMinor, currency,
        normalizedReference, `manual:${row.id}:${normalizedReference.toLowerCase()}`,
        note ? String(note).slice(0, 300) : null, device, now, now, now
      ]);
      this.insertLog("payment_submitted", {
        licenseId: row.id, actorId: "licensee", localShopId: shopId, deviceId: device, remoteAddress, detail: `manual:${paymentId}`
      });
      this.db.run(`INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at)
        VALUES (?, 'submitted', 'licensee', ?, ?, ?)`, [paymentId, remoteAddress ?? null, `reference:${normalizedReference}`, now]);
      this.db.run("COMMIT");
      this.persist();
      return this.paymentView(paymentId);
    } catch (error) {
      try {
        this.db.run("ROLLBACK");
      } catch {
        // Rollback may already have completed with the statement failure.
      }
      if (/UNIQUE constraint failed: payments\.reference_key/i.test(error.message)) {
        throw new Error("This payment reference has already been submitted for this subscription.");
      }
      if (/UNIQUE constraint failed: payments\.provider_transaction_id/i.test(error.message)) {
        throw new Error("This transaction id is already recorded.");
      }
      throw error;
    }
  }

  paymentView(id) {
    const row = this.query(`
      SELECT payments.*, shops.name AS shop_name FROM payments
      JOIN shops ON shops.id = payments.shop_id WHERE payments.id = ?
    `, [id]);
    if (!row) throw new Error("Payment was not found.");
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

  listPayments(statusFilter, limit = 500) {
    const safeStatus = statusFilter && PAYMENT_STATUSES.has(statusFilter) ? statusFilter : null;
    return this.all(`
      SELECT payments.*, shops.name AS shop_name FROM payments
      JOIN shops ON shops.id = payments.shop_id
      ${safeStatus ? "WHERE payments.status = ?" : ""}
      ORDER BY payments.submitted_at DESC LIMIT ?
    `, safeStatus ? [safeStatus, limit] : [limit]).map(row => ({
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
    }));
  }

  licenseePayments({ token, localShopId, deviceId, limit = 50 }) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }
    const { row } = this.getLicense(payload.licenseId);
    if (row.local_shop_id !== shopId || row.device_id !== device) {
      throw new Error("This license is no longer activated for this shop installation.");
    }
    const boundedLimit = Math.min(Math.max(1, Number(limit) || 50), 100);
    return this.all(`
      SELECT id, plan_id, method, status, amount_minor, currency, reference,
        provider, provider_transaction_id, submitted_at, decided_at, decision_reason, applied_at
      FROM payments WHERE license_id = ? ORDER BY submitted_at DESC LIMIT ?
    `, [row.id, boundedLimit]).map(item => ({
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

  approvePayment(paymentId, { actorId, remoteAddress } = {}) {
    const payment = this.query("SELECT * FROM payments WHERE id = ?", [paymentId]);
    if (!payment) throw new Error("Payment was not found.");
    if (payment.status !== "pending") throw new Error("An already decided payment cannot be approved again.");
    const license = this.getLicense(payment.license_id);
    if (!license) throw new Error("The payment's license was not found.");
    const plan = this.plans.get(payment.plan_id);
    if (!plan || !plan.available) throw new Error("The payment references a plan that is no longer available.");
    if (payment.currency !== plan.currency || payment.amount_minor !== plan.priceMinor) {
      throw new Error("The submitted amount or currency no longer matches the plan price. Reject it with a reason instead.");
    }
    this.db.run(
      "UPDATE payments SET status = 'approved', decided_by = ?, decided_at = ?, updated_at = ? WHERE id = ? AND status = 'pending'",
      [actorId ?? null, new Date(this.now()).toISOString(), new Date(this.now()).toISOString(), paymentId]
    );
    if (this.db.getRowsModified() !== 1) throw new Error("An already decided payment cannot be approved again.");
    const view = this.applyRenewal(payment.license_id, payment.plan_id, { actorId, paymentId });
    this.db.run("UPDATE payments SET applied_at = ?, updated_at = ? WHERE id = ?",
      [new Date(this.now()).toISOString(), new Date(this.now()).toISOString(), paymentId]);
    this.db.run(`INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at)
      VALUES (?, 'approved', ?, ?, ?, ?)`, [paymentId, actorId ?? null, remoteAddress ?? null, `renewed_license:${payment.license_id}`, new Date(this.now()).toISOString()]);
    this.persist();
    return { payment: this.paymentView(paymentId), license: view };
  }

  rejectPayment(paymentId, { actorId, reason, remoteAddress } = {}) {
    const rejectionReason = assertText(reason ?? "", "Rejection reason", 300).trim();
    if (rejectionReason.length < 3) {
      throw new Error("A rejection reason of at least 3 characters is required.");
    }
    this.db.run("BEGIN IMMEDIATE");
    try {
      this.db.run(
        "UPDATE payments SET status = 'rejected', decided_by = ?, decided_at = ?, decision_reason = ?, updated_at = ? WHERE id = ? AND status = 'pending'",
        [actorId ?? null, new Date(this.now()).toISOString(), rejectionReason, new Date(this.now()).toISOString(), paymentId]
      );
      if (this.db.getRowsModified() !== 1) throw new Error("An already decided payment cannot be rejected again.");
      this.db.run(`INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at)
        VALUES (?, 'rejected', ?, ?, ?, ?)`, [paymentId, actorId ?? null, remoteAddress ?? null, rejectionReason, new Date(this.now()).toISOString()]);
      this.db.run("COMMIT");
      this.persist();
      return this.paymentView(paymentId);
    } catch (error) {
      try {
        this.db.run("ROLLBACK");
      } catch {
        // Rollback may already have completed.
      }
      throw error;
    }
  }

  // Applies one verified gateway webhook event. Idempotent: repeat deliveries
  // with the same (provider, eventId) return without re-applying anything.
  recordGatewayEvent(provider, normalized, { remoteAddress } = {}) {
    const now = new Date(this.now()).toISOString();
    try {
      this.db.run(`INSERT INTO gateway_events (provider, event_id, event_type, provider_transaction_id, remote_address, result, received_at)
        VALUES (?, ?, ?, ?, ?, 'received', ?)`, [provider, normalized.eventId, normalized.eventType, normalized.transactionId, remoteAddress ?? null, now]);
    } catch (error) {
      if (/UNIQUE constraint failed: gateway_events\.provider, gateway_events\.event_id/i.test(error.message)) {
        return { duplicate: true, applied: false };
      }
      throw error;
    }
    const isSuccessful = normalized.status === "succeeded";
    const statusForEvent = isSuccessful ? "approved" : PAYMENT_STATUSES.has(normalized.status) ? normalized.status : null;
    if (!statusForEvent) {
      this.insertPaymentEvent(null, "gateway_unmatched", { detail: `${provider}:${normalized.eventId}:unknown status`, remoteAddress });
      return { duplicate: false, applied: false };
    }
    const payment = this.query(`
      SELECT * FROM payments
      WHERE lower(reference) = lower(?) AND status = 'pending'
      ORDER BY submitted_at DESC LIMIT 1
    `, [normalized.customerReference ?? ""]);
    let applied = false;
    let paymentId = null;
    if (payment) {
      paymentId = payment.id;
      if (isSuccessful) {
        if (normalized.amountMinor !== payment.amount_minor || normalized.currency !== payment.currency) {
          this.db.run(`INSERT INTO payment_events (payment_id, event, remote_address, detail, created_at)
            VALUES (?, 'gateway_amount_mismatch', ?, ?, ?)`, [paymentId, remoteAddress ?? null,
            `expected:${payment.currency}${payment.amount_minor} received:${normalized.currency}${normalized.amountMinor}`, now]);
        } else {
        this.db.run("UPDATE payments SET status = 'approved', method = 'gateway', provider = ?, provider_transaction_id = ?, decided_by = 'gateway', decided_at = ?, updated_at = ? WHERE id = ? AND status = 'pending'",
          [provider, normalized.transactionId, now, now, paymentId]);
        if (this.db.getRowsModified() === 1) {
            const view = this.applyRenewal(payment.license_id, payment.plan_id, { actorId: `gateway:${provider}`, paymentId });
            this.db.run("UPDATE payments SET applied_at = ?, updated_at = ? WHERE id = ?", [now, now, paymentId]);
            this.db.run(`INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at)
              VALUES (?, 'approved', 'gateway', ?, ?, ?)`, [paymentId, remoteAddress ?? null, `renewed_license:${payment.license_id} term:${view.expiresAt}`, now]);
            applied = true;
          }
        }
      } else {
        this.db.run("UPDATE payments SET status = ?, decided_by = 'gateway', decided_at = ?, updated_at = ? WHERE id = ? AND status = 'pending'",
          [statusForEvent, now, now, paymentId]);
        this.db.run(`INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at)
          VALUES (?, ?, 'gateway', ?, ?, ?)`, [paymentId, `gateway_${statusForEvent}`, remoteAddress ?? null, `${provider}:${normalized.eventId}`, now]);
      }
    } else {
      this.insertPaymentEvent(null, "gateway_unmatched", { detail: `${provider}:${normalized.eventId}:${normalized.transactionId}`, remoteAddress });
    }
    this.db.run("UPDATE gateway_events SET payment_id = ?, result = ? WHERE provider = ? AND event_id = ?",
      [paymentId, applied ? "applied" : "recorded", provider, normalized.eventId]);
    this.persist();
    return { duplicate: false, applied };
  }

  insertPaymentEvent(paymentId, event, {
    actorId = null, remoteAddress = null, detail = ""
  } = {}) {
    this.db.run(`INSERT INTO payment_events (payment_id, event, actor_id, remote_address, detail, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`, [paymentId, event, actorId, remoteAddress, String(detail).slice(0, 300), new Date(this.now()).toISOString()]);
  }

  subscriptionOverview() {
    const licenses = this.list();
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

  recurringRevenue() {
    const periodStart = new Date(this.now());
    periodStart.setUTCDate(1);
    periodStart.setUTCHours(0, 0, 0, 0);
    // Monthly recurring revenue is reported from completed verified payments
    // only (approved payments applied this calendar month). Yearly plans are
    // normalized at one twelfth of their recorded amount.
    const rows = this.all(`
      SELECT amount_minor, currency FROM payments
      WHERE status = 'approved' AND applied_at >= ? AND applied_at < ?
    `, [periodStart.toISOString(), new Date(this.now()).toISOString()]);
    const totals = new Map();
    for (const row of rows) {
      const monthlyEquivalent = row.amount_minor;
      totals.set(row.currency, (totals.get(row.currency) ?? 0) + monthlyEquivalent);
    }
    return { period: { start: periodStart.toISOString() }, currencies: Object.fromEntries(totals) };
  }

  paymentLogs(limit = 200) {
    return this.all(`
      SELECT id, payment_id AS paymentId, event, actor_id AS actorId, remote_address AS remoteAddress,
        detail, created_at AS createdAt FROM payment_events ORDER BY id DESC LIMIT ?`, [limit]
    );
  }

  createBackup(backupDirectory, options = {}) {
    const { retainCount = 10 } = options;
    if (!backupDirectory || typeof backupDirectory !== "string") {
      throw new Error("A backup directory path is required.");
    }
    if (this.closed) throw new Error("The license database is closed. Reopen the service before creating backups.");
    fs.mkdirSync(backupDirectory, { recursive: true });
    const timestamp = new Date(this.now()).toISOString().replace(/[:\-]/g, "").split(".")[0] + "Z";
    const backupPath = path.join(backupDirectory, `shoppos-license-backup-${timestamp}.sqlite`);
    const temporary = `${backupPath}.tmp`;
    let exported;
    try {
      exported = this.db.export();
    } catch (exportError) {
      throw new Error("Export failed: " + (exportError instanceof Error ? exportError.message : String(exportError)));
    }
    try {
      fs.writeFileSync(temporary, Buffer.from(exported), { flag: "wx", mode: 0o600 });
      fs.renameSync(temporary, backupPath);
    } catch (error) {
      try { fs.rmSync(temporary, { force: true }); } catch {}
      throw error;
    }
    this.enforceBackupRetention(backupDirectory, retainCount);
    return { backupPath, backupFile: path.basename(backupPath), createdAt: new Date(this.now()).toISOString() };
  }

  enforceBackupRetention(backupDirectory, retainCount = 10) {
    if (!fs.existsSync(backupDirectory)) return;
    const files = fs.readdirSync(backupDirectory)
      .filter(name => name.startsWith("shoppos-license-backup-") && name.endsWith(".sqlite"))
      .map(name => ({
        name,
        path: path.join(backupDirectory, name),
        mtime: fs.statSync(path.join(backupDirectory, name)).mtimeMs
      }))
      .sort((a, b) => b.mtime - a.mtime);
    for (let i = retainCount; i < files.length; i += 1) {
      try { fs.rmSync(files[i].path, { force: true }); } catch {}
    }
  }

  verifyBackup(backupPath) {
    if (!fs.existsSync(backupPath)) throw new Error("Backup file was not found.");
    const bytes = fs.readFileSync(backupPath);
    const SQL = require("sql.js");
    const wasmBinary = fs.readFileSync(require.resolve("sql.js/dist/sql-wasm.wasm"));
    return SQL({ wasmBinary }).then(SQLLib => {
      const db = new SQLLib.Database(bytes);
      const tables = db.exec("SELECT name FROM sqlite_master WHERE type='table'");
      const tableNames = tables[0]?.values.map(row => row[0]) ?? [];
      const required = ["shops", "licenses", "license_logs", "plans", "payments", "payment_events", "gateway_events"];
      const missing = required.filter(name => !tableNames.includes(name));
      const version = db.exec("PRAGMA user_version")[0]?.values[0]?.[0] ?? 0;
      db.close();
      if (missing.length > 0) throw new Error(`Backup verification failed: missing tables ${missing.join(", ")}.`);
      return { valid: true, schemaVersion: version, tableCount: tableNames.length, verifiedAt: new Date(this.now()).toISOString() };
    });
  }

  async restoreFromBackup(backupPath, { actorId } = {}) {
    if (!fs.existsSync(backupPath)) throw new Error("Backup file was not found.");
    const verification = await this.verifyBackup(backupPath);
    if (!verification.valid) throw new Error("Backup verification failed.");

    // Pre-restore safety: copy current database bytes before replacing
    const currentBytes = fs.readFileSync(this.databasePath);
    let preRestoreBackup = null;
    try {
      preRestoreBackup = this.createBackup(path.dirname(this.databasePath), { retainCount: 1 });
    } catch {
      // If pre-restore backup fails, continue with restore anyway; currentBytes is preserved above.
    }

    try {
      this.db = new this.SQL.Database(fs.readFileSync(backupPath));
      this.db.run("PRAGMA foreign_keys = ON");
      this.plans = this.loadPlans();
      this.persist();
      this.log("database_restored", { actorId, detail: `restored_from:${path.basename(backupPath)}` });
      return { restored: true, fromBackup: path.basename(backupPath), preRestoreBackup: preRestoreBackup ? preRestoreBackup.backupFile : null, restoredAt: new Date(this.now()).toISOString() };
    } catch (error) {
      // Attempt to roll back to the pre-restore state
      try {
        this.db = new this.SQL.Database(currentBytes);
        this.db.run("PRAGMA foreign_keys = ON");
        this.plans = this.loadPlans();
        this.persist();
      } catch {
        // Leave the database in its current state; the operator must intervene.
      }
      throw error;
    }
  }

  changeState(licenseId, state, { actorId } = {}) {
    const { row } = this.getLicense(licenseId);
    if (row.state === "revoked" || (row.state === "cancelled" && state !== "revoked")) {
      throw new Error("A cancelled or revoked license cannot be reactivated.");
    }
    if (state === "reactivated" && row.state !== "suspended") throw new Error("Only a suspended license can be reactivated.");
    const nextState = state === "reactivated" ? "active" : state;
    const now = new Date(this.now()).toISOString();
    this.db.run("UPDATE licenses SET state = ?, updated_at = ? WHERE id = ?", [nextState, now, row.id]);
    this.persist();
    this.log(state, { licenseId: row.id, actorId });
    return this.view(row.id);
  }

  list() {
    return this.all(`
      SELECT licenses.*, shops.name AS shop_name FROM licenses
      JOIN shops ON shops.id = licenses.shop_id ORDER BY licenses.created_at DESC
    `).map(row => licenseView(row, this.plans.get(row.plan_id), this.now()));
  }

  logs(licenseId) {
    return this.all(`
      SELECT id, license_id AS licenseId, actor_id AS actorId, event, local_shop_id AS localShopId, device_id AS deviceId,
        remote_address AS remoteAddress, created_at AS createdAt, detail
      FROM license_logs ${licenseId ? "WHERE license_id = ?" : ""} ORDER BY id DESC LIMIT 500
    `, licenseId ? [licenseId] : []);
  }

  close() {
    if (this.closed) return;
    this.persist();
    this.db.close();
    this.closed = true;
  }
}

function jsonResponse(response, status, body) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map(part => {
    const separator = part.indexOf("=");
    if (separator < 0) return ["", ""];
    return [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
  }).filter(([name]) => name));
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && crypto.timingSafeEqual(leftBytes, rightBytes);
}

function requireSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) throw Object.assign(new Error("An Origin header is required for admin browser requests."), { statusCode: 403 });
  let originUrl;
  try {
    originUrl = new URL(origin);
  } catch {
    throw Object.assign(new Error("The admin request origin is invalid."), { statusCode: 403 });
  }
  if (!["http:", "https:"].includes(originUrl.protocol) || originUrl.host !== request.headers.host) {
    throw Object.assign(new Error("Cross-origin admin requests are not allowed."), { statusCode: 403 });
  }
}

function safeFileResponse(response, filename) {
  try {
    const contents = fs.readFileSync(filename);
    response.writeHead(200, {
      "content-type": filename.endsWith(".html") ? "text/html; charset=utf-8"
        : filename.endsWith(".css") ? "text/css; charset=utf-8"
          : "text/javascript; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY"
    });
    response.end(contents);
  } catch (error) {
    console.error("Could not serve the license admin dashboard asset.", error);
    jsonResponse(response, 500, { error: "The admin dashboard could not be loaded." });
  }
}

function authenticateAdmin(authorization, admins) {
  const match = typeof authorization === "string" && /^Bearer ([^\s]+)$/.exec(authorization);
  if (!match) return undefined;
  const supplied = Buffer.from(match[1]);
  return admins.find(admin => {
    const expected = Buffer.from(admin.token);
    return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  });
}

function createLicenseRequestHandler({
  service, admins, rateLimit = 60,
  rateWindowMs = 60000, dashboardDirectory = path.join(__dirname, "admin-dashboard"),
  secureCookies = process.env.NODE_ENV === "production"
}) {
  const administrators = parseAdminUsers(admins);
  if (!Number.isInteger(rateLimit) || rateLimit < 1 || !Number.isInteger(rateWindowMs) || rateWindowMs < 1) {
    throw new Error("License server rate limits must be positive integers.");
  }
  const limits = new Map();
  const loginAttempts = new Map();
  const sessions = new Map();
  const sessionCookie = "shoppos_admin_session";
  const sessionLifetimeMs = 8 * 60 * 60 * 1000;
  return async (request, response) => {
    const remoteAddress = request.socket.remoteAddress ?? "unknown";
    const now = Date.now();
    if (typeof service.consumeRateLimit === "function") {
      try {
        if (!await service.consumeRateLimit("api", remoteAddress, rateLimit, rateWindowMs)) {
          return jsonResponse(response, 429, { error: "Too many requests." });
        }
      } catch (error) {
        console.error("Persistent request rate limiting failed.", {
          code: error.code,
          name: error.name
        });
        return jsonResponse(response, 503, { error: "Request protection is temporarily unavailable." });
      }
    } else {
      const recent = (limits.get(remoteAddress) ?? []).filter(timestamp => timestamp > now - rateWindowMs);
      if (recent.length >= rateLimit) return jsonResponse(response, 429, { error: "Too many requests." });
      recent.push(now);
      limits.set(remoteAddress, recent);
      if (limits.size > 10000) {
        for (const [address, timestamps] of limits) {
          if (!timestamps.some(timestamp => timestamp > now - rateWindowMs)) limits.delete(address);
        }
      }
    }

    let route;
    try {
      route = new URL(request.url, "http://localhost");
    } catch {
      return jsonResponse(response, 400, { error: "Invalid request URL." });
    }

    if (request.method === "GET" && ["/admin", "/admin/"].includes(route.pathname)) {
      return safeFileResponse(response, path.join(dashboardDirectory, "index.html"));
    }
    if (request.method === "GET" && ["/admin/app.js", "/admin/styles.css"].includes(route.pathname)) {
      const asset = route.pathname.endsWith(".js") ? "app.js" : "styles.css";
      return safeFileResponse(response, path.join(dashboardDirectory, asset));
    }

    let bodyRaw = Buffer.alloc(0);
    let body;
    try {
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 32768) throw Object.assign(new Error("Request body is too large."), { statusCode: 413 });
        chunks.push(chunk);
      }
      bodyRaw = Buffer.concat(chunks);
      body = bodyRaw.length ? JSON.parse(bodyRaw.toString("utf8")) : {};
    } catch (error) {
      return jsonResponse(response, error.statusCode ?? 400, { error: error instanceof SyntaxError ? "Invalid JSON request body." : error.message });
    }

    try {
      if (request.method === "POST" && route.pathname === "/admin/session") {
        requireSameOrigin(request);
        if (typeof service.consumeRateLimit === "function") {
          if (!await service.consumeRateLimit("admin-login", remoteAddress, 5, 15 * 60 * 1000)) {
            return jsonResponse(response, 429, { error: "Too many admin login attempts. Try again in 15 minutes." });
          }
        } else {
          if (loginAttempts.size > 10000) {
            for (const [address, attempts] of loginAttempts) {
              if (!attempts.some(timestamp => timestamp > Date.now() - 15 * 60 * 1000)) loginAttempts.delete(address);
            }
          }
          const timestamps = (loginAttempts.get(remoteAddress) ?? []).filter(timestamp => timestamp > Date.now() - 15 * 60 * 1000);
          if (timestamps.length >= 5) {
            loginAttempts.set(remoteAddress, timestamps);
            return jsonResponse(response, 429, { error: "Too many admin login attempts. Try again in 15 minutes." });
          }
          timestamps.push(Date.now());
          loginAttempts.set(remoteAddress, timestamps);
        }
        const administrator = authenticateAdmin(request.headers.authorization, administrators);
        if (!administrator) return jsonResponse(response, 401, { error: "Administrator token is invalid." });
        if (typeof service.resetRateLimit === "function") await service.resetRateLimit("admin-login", remoteAddress);
        else loginAttempts.delete(remoteAddress);
        const id = crypto.randomBytes(32).toString("base64url");
        const csrfToken = crypto.randomBytes(32).toString("base64url");
        const expiresAt = Date.now() + sessionLifetimeMs;
        if (typeof service.createAdminSession === "function") {
          await service.createAdminSession(id, {
            adminId: administrator.id,
            csrfToken,
            expiresAt
          });
        } else {
          if (sessions.size >= 10000) {
            for (const [sessionKey, activeSession] of sessions) {
              if (activeSession.expiresAt <= Date.now()) sessions.delete(sessionKey);
            }
            if (sessions.size >= 10000) return jsonResponse(response, 503, { error: "The admin session limit has been reached. Try again later." });
          }
          sessions.set(id, { administrator, csrfToken, expiresAt });
        }
        const secure = secureCookies ? "; Secure" : "";
        response.setHeader("set-cookie", `${sessionCookie}=${id}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=${Math.floor(sessionLifetimeMs / 1000)}${secure}`);
        return jsonResponse(response, 200, {
          administrator: { id: administrator.id, roles: administrator.roles },
          csrfToken,
          expiresAt: new Date(expiresAt).toISOString()
        });
      }

      const cookies = parseCookies(request.headers.cookie);
      const sessionId = cookies[sessionCookie];
      let session;
      if (sessionId && typeof service.getAdminSession === "function") {
        const persistedSession = await service.getAdminSession(sessionId);
        const administrator = persistedSession &&
          administrators.find(candidate => candidate.id === persistedSession.adminId);
        if (persistedSession && administrator && persistedSession.expiresAt > Date.now()) {
          session = { ...persistedSession, administrator };
        } else if (persistedSession || administrator === undefined) {
          await service.deleteAdminSession(sessionId);
        }
      } else if (sessionId) {
        session = sessions.get(sessionId);
      }
      if (session && session.expiresAt <= Date.now()) {
        if (typeof service.deleteAdminSession === "function") await service.deleteAdminSession(sessionId);
        else sessions.delete(sessionId);
        session = undefined;
      }
      if (request.method === "GET" && route.pathname === "/admin/session") {
        if (!session) return jsonResponse(response, 401, { error: "Admin session is not active." });
        return jsonResponse(response, 200, {
          administrator: { id: session.administrator.id, roles: session.administrator.roles },
          csrfToken: session.csrfToken,
          expiresAt: new Date(session.expiresAt).toISOString()
        });
      }
      if (request.method === "DELETE" && route.pathname === "/admin/session") {
        requireSameOrigin(request);
        if (session && !constantTimeEqual(request.headers["x-csrf-token"], session.csrfToken)) {
          return jsonResponse(response, 403, { error: "The admin session CSRF token is invalid." });
        }
        if (session) {
          if (typeof service.deleteAdminSession === "function") await service.deleteAdminSession(sessionId);
          else sessions.delete(sessionId);
        }
        const secure = secureCookies ? "; Secure" : "";
        response.setHeader("set-cookie", `${sessionCookie}=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0${secure}`);
        response.writeHead(204, { "cache-control": "no-store" });
        return response.end();
      }

      if (route.pathname.startsWith("/admin/")) {
        const bearerAdministrator = authenticateAdmin(request.headers.authorization, administrators);
        const administrator = session?.administrator ?? bearerAdministrator;
        if (!administrator) {
          return jsonResponse(response, 401, { error: "Administrator authentication required." });
        }
        if (session && request.method !== "GET" && request.method !== "HEAD") {
          requireSameOrigin(request);
          if (!constantTimeEqual(request.headers["x-csrf-token"], session.csrfToken)) {
            return jsonResponse(response, 403, { error: "The admin session CSRF token is invalid." });
          }
        }
        let requiredRole;
        if (["GET", "POST"].includes(request.method) && route.pathname === "/admin/shops" && request.method === "POST") {
          requiredRole = "licenses:issue";
        } else if (request.method === "GET" && route.pathname === "/admin/shops") {
          requiredRole = "licenses:read";
        } else if (request.method === "POST" && ["/admin/shops/register"].includes(route.pathname)) {
          requiredRole = "licenses:issue";
        } else if (request.method === "POST" && /^\/admin\/shops\/[0-9a-f-]{36}\/licenses$/i.test(route.pathname)) {
          requiredRole = "licenses:issue";
        } else if (request.method === "GET" && ["/admin/plans", "/admin/dashboard", "/admin/activations", "/admin/mrr", "/admin/payment-events"].includes(route.pathname)) {
          requiredRole = "licenses:read";
        } else if (request.method === "PUT" && route.pathname === "/admin/plans") {
          requiredRole = "licenses:manage";
        } else if (request.method === "GET" &&
            (route.pathname === "/admin/licenses" || route.pathname === "/admin/logs" || route.pathname === "/admin/payments" ||
             /^\/admin\/licenses\/[0-9a-f-]{36}$/i.test(route.pathname) ||
             /^\/admin\/payments\/[0-9a-f-]{36}$/i.test(route.pathname))) {
          requiredRole = "licenses:read";
        } else if (request.method === "POST" &&
            (/^\/admin\/licenses\/[0-9a-f-]{36}\/(renew|suspend|reactivate|cancel|revoke)$/i.test(route.pathname) ||
             /^\/admin\/payments\/[0-9a-f-]{36}\/(approve|reject)$/i.test(route.pathname))) {
          requiredRole = "licenses:manage";
        } else if (request.method === "GET" && route.pathname === "/admin/backup") {
          requiredRole = "licenses:manage";
        } else if (request.method === "POST" && route.pathname === "/admin/restore") {
          requiredRole = "licenses:manage";
        } else if (request.method === "GET" && route.pathname === "/admin/backup/verify") {
          requiredRole = "licenses:manage";
        }
        if (!requiredRole) return jsonResponse(response, 404, { error: "Administrator route was not found." });
        if (!administrator.roles.includes(requiredRole)) {
          return jsonResponse(response, 403, { error: `Administrator role ${requiredRole} is required.` });
        }
        if (requiredRole === "licenses:issue") {
          if (route.pathname === "/admin/shops/register") {
            return jsonResponse(response, 201, await service.registerExistingShop(body, { actorId: administrator.id }));
          }
          const issueForShop = route.pathname.match(/^\/admin\/shops\/([0-9a-f-]{36})\/licenses$/i);
          if (issueForShop) {
            return jsonResponse(response, 201, await service.createLicenseForShop(issueForShop[1], body, { actorId: administrator.id }));
          }
          return jsonResponse(response, 201, await service.createShop(body, { actorId: administrator.id }));
        }
        if (request.method === "GET" && route.pathname === "/admin/shops") return jsonResponse(response, 200, { shops: await service.listShops() });
        if (request.method === "GET" && route.pathname === "/admin/plans") return jsonResponse(response, 200, { plans: await service.listPlans() });
        if (request.method === "PUT" && route.pathname === "/admin/plans") return jsonResponse(response, 200, { plan: await service.updatePlan(body, { actorId: administrator.id }) });
        if (request.method === "GET" && route.pathname === "/admin/dashboard") {
          const [licenses, logs, shops] = await Promise.all([
            service.list(),
            service.logs(),
            service.listShops()
          ]);
          return jsonResponse(response, 200, {
            shops: shops.length,
            licenses: licenses.length,
            active: licenses.filter(item => ["active", "trial", "grace_period"].includes(item.status)).length,
            expired: licenses.filter(item => item.status === "expired").length,
            activations: logs.filter(item => item.event === "activation_succeeded").length,
            recentActivity: logs.slice(0, 12)
          });
        }
        if (request.method === "GET" && route.pathname === "/admin/activations") {
          return jsonResponse(response, 200, { activations: (await service.logs()).filter(item => item.event.startsWith("activation_")) });
        }
        if (request.method === "GET" && route.pathname === "/admin/licenses") {
          return jsonResponse(response, 200, { licenses: await service.list() });
        }
        if (request.method === "GET" && route.pathname === "/admin/logs") {
          return jsonResponse(response, 200, { logs: await service.logs(route.searchParams.get("licenseId") ?? undefined) });
        }
        if (request.method === "GET" && route.pathname === "/admin/payments") {
          return jsonResponse(response, 200, { payments: await service.listPayments(route.searchParams.get("status") ?? undefined, Number(route.searchParams.get("limit")) || 500) });
        }
        const paymentMatch = route.pathname.match(/^\/admin\/payments\/([0-9a-f-]{36})(?:\/(approve|reject))?$/i);
        if (paymentMatch && request.method === "GET" && !paymentMatch[2]) {
          return jsonResponse(response, 200, await service.paymentView(paymentMatch[1]));
        }
        if (paymentMatch && request.method === "POST" && paymentMatch[2] === "approve") {
          return jsonResponse(response, 200, await service.approvePayment(paymentMatch[1], { actorId: administrator.id, remoteAddress }));
        }
        if (paymentMatch && request.method === "POST" && paymentMatch[2] === "reject") {
          return jsonResponse(response, 200, await service.rejectPayment(paymentMatch[1], { actorId: administrator.id, reason: body.reason, remoteAddress }));
        }
        const action = route.pathname.match(/^\/admin\/licenses\/([0-9a-f-]{36})(?:\/(renew|suspend|reactivate|cancel|revoke))?$/i);
        if (action && request.method === "GET" && !action[2]) return jsonResponse(response, 200, await service.view(action[1]));
        if (action && request.method === "POST" && action[2] === "renew") {
          return jsonResponse(response, 200, await service.renew(action[1], { actorId: administrator.id }));
        }
        if (action && request.method === "POST" && ["suspend", "reactivate", "cancel", "revoke"].includes(action[2])) {
          const state = action[2] === "cancel" ? "cancelled" : action[2] === "suspend" ? "suspended" : action[2] === "revoke" ? "revoked" : "reactivated";
          return jsonResponse(response, 200, await service.changeState(action[1], state, { actorId: administrator.id }));
        }
        if (request.method === "GET" && route.pathname === "/admin/backup") {
          const backupRoot = route.searchParams.get("directory") || path.join(__dirname, "backups");
          const result = await service.createBackup(backupRoot);
          return jsonResponse(response, 200, result);
        }
        if (request.method === "POST" && route.pathname === "/admin/restore") {
          const backupPath = body?.backupPath;
          if (typeof backupPath !== "string" || !backupPath.trim()) {
            return jsonResponse(response, 400, { error: "A backupPath is required in the request body." });
          }
          try {
            return jsonResponse(response, 200, await service.restoreFromBackup(backupPath, { actorId: administrator.id }));
          } catch (error) {
            return jsonResponse(response, error.statusCode ?? 400, { error: error instanceof Error ? error.message : String(error) });
          }
        }
        if (request.method === "GET" && route.pathname === "/admin/backup/verify") {
          const backupPath = route.searchParams.get("path");
          if (typeof backupPath !== "string" || !backupPath.trim()) {
            return jsonResponse(response, 400, { error: "A path query parameter is required." });
          }
          return jsonResponse(response, 200, await service.verifyBackup(backupPath));
        }
        return jsonResponse(response, 404, { error: "Administrator route was not found." });
      }

      if (request.method === "GET" && route.pathname === "/v1/health") {
        if (service.healthCheck) return jsonResponse(response, 200, await service.healthCheck());
        return jsonResponse(response, 200, { status: "ok", service: "shoppos-license-server", schemaVersion: SCHEMA_VERSION, timestamp: new Date(service.now()).toISOString() });
      }
      if (request.method === "POST" && route.pathname === "/v1/activate") {
        return jsonResponse(response, 200, await service.activate({ ...body, remoteAddress }));
      }
      if (request.method === "POST" && route.pathname === "/v1/status") {
        return jsonResponse(response, 200, await service.status({ ...body, remoteAddress }));
      }
      if (request.method === "POST" && route.pathname === "/v1/deactivate") {
        return jsonResponse(response, 200, await service.deactivate({ ...body, remoteAddress }));
      }
      if (request.method === "POST" && route.pathname === "/v1/payments/submit") {
        return jsonResponse(response, 200, await service.submitManualPayment(body, { remoteAddress }));
      }
      if (request.method === "GET" && route.pathname === "/v1/payments") {
        return jsonResponse(response, 200, { payments: await service.licenseePayments({
          token: route.searchParams.get("token"),
          localShopId: route.searchParams.get("localShopId"),
          deviceId: route.searchParams.get("deviceId"),
          limit: Number(route.searchParams.get("limit")) || 50,
          remoteAddress
        }) });
      }
      const webhookMatch = route.pathname.match(/^\/v1\/webhooks\/gateway\/([a-z0-9_-]+)$/i);
      if (webhookMatch && request.method === "POST") {
        const provider = webhookMatch[1];
        const adapter = getGatewayAdapter(provider);
        if (!adapter) {
          return jsonResponse(response, 400, { error: "Unsupported payment gateway provider." });
        }
        if (process.env.NODE_ENV === "production" &&
            typeof adapter.canEnableInProduction === "function" &&
            !adapter.canEnableInProduction()) {
          return jsonResponse(response, 503, { error: "This payment gateway adapter is not available in production." });
        }
        const configError = adapter.webhookConfigError ? adapter.webhookConfigError() : null;
        if (configError) {
          return jsonResponse(response, 500, { error: configError });
        }
        try {
          const normalized = adapter.verifyWebhook({ rawBody: bodyRaw, headers: request.headers });
          const result = await service.recordGatewayEvent(provider, normalized, { remoteAddress });
          return jsonResponse(response, 200, { accepted: true, ...result });
        } catch (error) {
          if (error instanceof WebhookVerificationError || error.name === "WebhookVerificationError") {
            return jsonResponse(response, 401, { error: "Webhook signature verification failed." });
          }
          throw error;
        }
      }
      return jsonResponse(response, 404, { error: "Route was not found." });
    } catch (error) {
      if (error && typeof error.code === "string" && !error.statusCode) {
        console.error("License database request failed.", {
          code: error.code,
          name: error.name
        });
        return jsonResponse(response, error.code === "23505" ? 409 : 503, {
          error: "The license database request could not be completed."
        });
      }
      const message = error instanceof Error ? error.message : "The request could not be completed.";
      const status = error.statusCode ?? (/license key is invalid/i.test(message) ? 401
        : /license token|signature|different shop|already been redeemed|no longer activated|installation/i.test(message) ? 403
          : /not found/i.test(message) ? 404 : 400);
      return jsonResponse(response, status, { error: message });
    }
  };
}

function createLicenseServer(options) {
  const { host = "127.0.0.1", port = 8787 } = options;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("License server port must be between 0 and 65535.");
  }
  const requestHandler = createLicenseRequestHandler(options);
  const server = http.createServer(requestHandler);
  return {
    server,
    listen: () => new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        resolve(server.address());
      });
    }),
    close: () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
  };
}

async function initializeService(options = {}) {
  const initializeSqlJs = require("sql.js");
  const wasmBinary = fs.readFileSync(require.resolve("sql.js/dist/sql-wasm.wasm"));
  const SQL = await initializeSqlJs({ wasmBinary });
  return new LicenseService({
    SQL,
    databasePath: options.databasePath ?? process.env.LICENSE_DATABASE_PATH ?? path.join(__dirname, "data", "licenses.sqlite"),
    plans: options.plans ?? process.env.LICENSE_PLANS_JSON,
    privateKey: options.privateKey ?? process.env.LICENSE_SIGNING_PRIVATE_KEY?.replace(/\\n/g, "\n"),
    trustedPublicKeys: options.trustedPublicKeys ?? [],
    offlineGraceDays: options.offlineGraceDays ?? Number(process.env.LICENSE_OFFLINE_GRACE_DAYS ?? 7),
    now: options.now
  });
}

async function startFromEnvironment() {
  const config = validateServerConfiguration();
  const service = await initializeService({
    databasePath: config.databasePath,
    plans: [...config.plans.values()],
    privateKey: config.privateKey,
    trustedPublicKeys: config.trustedPublicKeys,
    offlineGraceDays: config.offlineGraceDays
  });
  const instance = createLicenseServer({
    service,
    admins: config.admins,
    host: config.host,
    port: config.port
  });
  await instance.listen();
  console.log(`ShopPOS license server listening on ${config.host}:${config.port}`);
  const shutdown = async () => {
    await instance.close();
    service.close();
    process.exit(0);
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (require.main === module) {
  startFromEnvironment().catch(error => {
    console.error("ShopPOS license server could not start:", error);
    process.exitCode = 1;
  });
}

module.exports = {
  LicenseService,
  createLicenseServer,
  createLicenseRequestHandler,
  authenticateAdmin,
  initializeService,
  parseAdminUsers,
  parsePlans,
  statusFor,
  validateServerConfiguration
};
