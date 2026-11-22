
const crypto = require("node:crypto");
const { createDatabase } = require("./database.cjs");
const { normalizePublicKeys, verifyWithTrustedPublicKeys } = require("../signing-keys.cjs");

const SUBSCRIPTION_GRACE_DAYS = 7;
const REQUIRED_SCHEMA_COLUMNS = {
  shops: ["id", "name", "local_shop_id", "verified_by", "verified_at", "created_at"],
  plans: ["id", "name", "interval", "price_minor", "currency", "trial_days", "grace_days", "available", "features_json", "max_devices", "max_staff", "updated_at"],
  licenses: ["id", "shop_id", "key_hash", "plan_id", "state", "starts_at", "expires_at", "trial_ends_at", "intended_local_shop_id", "key_redeemed_at", "local_shop_id", "device_id", "activated_at", "created_at", "updated_at"],
  license_logs: ["id", "license_id", "actor_id", "event", "local_shop_id", "device_id", "remote_address", "created_at", "detail"],
  payments: ["id", "shop_id", "license_id", "plan_id", "method", "status", "amount_minor", "currency", "reference", "reference_key", "provider", "provider_transaction_id", "note", "decision_reason", "submitted_by_device", "submitted_at", "decided_by", "decided_at", "applied_at", "created_at", "updated_at"],
  payment_events: ["id", "payment_id", "event", "actor_id", "remote_address", "detail", "created_at"],
  gateway_events: ["provider", "event_id", "event_type", "provider_transaction_id", "payment_id", "result", "remote_address", "received_at"]
};
const PAYMENT_STATUSES = new Set([
  "pending", "approved", "rejected", "failed", "refunded", "disputed"
]);

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

function parseJsonValue(value, label) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${label} contains invalid JSON.`);
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
    throw new Error("Configure at least one plan.");
  }

  const ids = new Set();

  for (const plan of plans) {
    if (
      !plan ||
      typeof plan.id !== "string" ||
      !/^[a-z0-9_-]{1,40}$/.test(plan.id) ||
      ids.has(plan.id) ||
      typeof plan.name !== "string" ||
      !plan.name.trim() ||
      !["monthly", "yearly"].includes(plan.interval) ||
      (plan.available !== undefined && typeof plan.available !== "boolean") ||
      !Number.isSafeInteger(plan.priceMinor) ||
      plan.priceMinor < 0 ||
      !validCurrency(plan.currency) ||
      !Number.isInteger(plan.trialDays ?? 0) ||
      (plan.trialDays ?? 0) < 0 ||
      (plan.trialDays ?? 0) > 365 ||
      !Number.isInteger(plan.graceDays ?? 0) ||
      (plan.graceDays ?? 0) < 0 ||
      (plan.graceDays ?? 0) > 60
    ) {
      throw new Error("Invalid subscription plan configuration.");
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

function addPeriod(isoDate, interval) {
  const date = new Date(isoDate);
  const day = date.getUTCDate();

  date.setUTCDate(1);
  date.setUTCMonth(date.getUTCMonth() + (interval === "yearly" ? 12 : 1));

  const lastDay = new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth() + 1,
    0
  )).getUTCDate();

  date.setUTCDate(Math.min(day, lastDay));
  return date.toISOString();
}

function statusFor(license, plan, now = Date.now()) {
  if (license.state !== "active") return license.state;

  if (license.trial_ends_at && now < Date.parse(license.trial_ends_at)) {
    return "trial";
  }

  const expiry = Date.parse(license.expires_at);

  if (now < expiry) return "active";
  if (now < expiry + plan.graceDays * 86400000) return "grace_period";

  return "expired";
}

function licenseView(row, plan, now) {
  if (!plan) {
    throw new Error("The license references a plan that is no longer configured.");
  }

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
  if (typeof token !== "string") {
    throw new Error("A signed license token is required.");
  }

  const parts = token.split(".");
  if (parts.length !== 2) throw new Error("Invalid license token.");

  try {
    return {
      payload: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
      encoded: parts[0],
      signature: Buffer.from(parts[1], "base64url")
    };
  } catch {
    throw new Error("Invalid license token.");
  }
}

function validShopId(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function assertShopId(value, label = "Shop ID") {
  if (!validShopId(value)) {
    throw new Error(`${label} must be a valid ShopPOS UUID.`);
  }
  return value.toLowerCase();
}

class PostgresLicenseService {
  constructor({
    database,
    plans,
    privateKey,
    trustedPublicKeys = [],
    offlineGraceDays = 7,
    requireFixedGrace = false,
    now = () => Date.now()
  }) {
    if (!Number.isInteger(offlineGraceDays) ||
        offlineGraceDays < 0 ||
        offlineGraceDays > 90) {
      throw new Error("LICENSE_OFFLINE_GRACE_DAYS must be between 0 and 90.");
    }

    if (!database) throw new Error("A PostgreSQL database connection is required.");

    this.db = database;
    this.configuredPlans = parsePlans(plans);
    this.plans = this.configuredPlans;
    this.privateKey = crypto.createPrivateKey(privateKey);

    if (this.privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error("LICENSE_SIGNING_PRIVATE_KEY must be an Ed25519 private key.");
    }

    this.publicKey = crypto.createPublicKey(this.privateKey);
    this.trustedPublicKeys = normalizePublicKeys([this.publicKey, ...trustedPublicKeys]);
    this.offlineGraceDays = offlineGraceDays;
    this.requireFixedGrace = requireFixedGrace;
    this.now = now;
    this.closed = false;
  }

  static async create(options = {}) {
    const ownsDatabase = !options.database || options.closeOnInitializationFailure === true;
    const database = options.database || createDatabase();
    let service;
    let stage = "service_construction";
    try {
      service = new PostgresLicenseService({
        ...options,
        database
      });
      stage = "schema_table_validation";
      await service.initialize();
      return service;
    } catch (error) {
      if (ownsDatabase) {
        try {
          await database.close();
        } catch (closeError) {
          console.error("Could not close PostgreSQL pool after initialization failed.", {
            code: closeError.code,
            name: closeError.name
          });
        }
      }
      const initializationError = new Error(
        error instanceof Error ? error.message : "PostgreSQL license service initialization failed.",
        { cause: error }
      );
      initializationError.startupStage = service?.initializationStage ?? stage;
      throw initializationError;
    }
  }

  async initialize() {
    this.initializationStage = "schema_table_validation";
    const schema = await this.db.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = current_schema()
       AND table_name = ANY($1::text[])`,
      [["shops", "plans", "licenses", "license_logs", "payments", "payment_events", "gateway_events"]]
    );
    const present = new Set(schema.rows.map(row => row.table_name));
    const missing = ["shops", "plans", "licenses", "license_logs", "payments", "payment_events", "gateway_events"]
      .filter(table => !present.has(table));
    if (missing.length) {
      throw new Error(`The PostgreSQL license schema is incomplete. Missing tables: ${missing.join(", ")}.`);
    }

    this.initializationStage = "schema_column_validation";
    const columnResult = await this.db.query(
      `SELECT table_name, column_name FROM information_schema.columns
       WHERE table_schema = current_schema()
       AND table_name = ANY($1::text[])`,
      [Object.keys(REQUIRED_SCHEMA_COLUMNS)]
    );
    const columns = new Map();
    for (const { table_name, column_name } of columnResult.rows) {
      if (!columns.has(table_name)) columns.set(table_name, new Set());
      columns.get(table_name).add(column_name);
    }
    const missingColumns = Object.entries(REQUIRED_SCHEMA_COLUMNS).flatMap(([table, required]) =>
      required.filter(column => !columns.get(table)?.has(column)).map(column => `${table}.${column}`)
    );
    if (missingColumns.length) {
      throw new Error(`The PostgreSQL license schema is incomplete. Missing columns: ${missingColumns.join(", ")}.`);
    }

    this.initializationStage = "support_table_initialization";
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS admin_sessions (
         session_hash CHAR(64) PRIMARY KEY,
         admin_id TEXT NOT NULL,
         csrf_token TEXT NOT NULL,
         expires_at TIMESTAMPTZ NOT NULL,
         created_at TIMESTAMPTZ NOT NULL
       )`
    );
    await this.db.query(
       `CREATE TABLE IF NOT EXISTS request_rate_limits (
          key_hash CHAR(64) PRIMARY KEY,
          window_start TIMESTAMPTZ NOT NULL,
          request_count INTEGER NOT NULL CHECK (request_count > 0)
        )`
    );
    await this.db.query("DELETE FROM request_rate_limits WHERE window_start < NOW() - INTERVAL '1 day'");

    this.initializationStage = "plan_seeding";
    await this.db.transaction(async client => {
      const current = await client.query("SELECT id FROM plans LIMIT 1");
      if (current.rows.length > 0) return;
      const now = new Date(this.now()).toISOString();
      for (const plan of this.configuredPlans.values()) {
        await client.query(
          `INSERT INTO plans
           (id, name, interval, price_minor, currency, trial_days, grace_days,
            available, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (id) DO NOTHING`,
          [
            plan.id,
            plan.name,
            plan.interval,
            plan.priceMinor,
            plan.currency,
            plan.trialDays,
            plan.graceDays,
            plan.available,
            now
          ]
        );
      }
    });

    this.initializationStage = "plan_loading";
    const result = await this.db.query(
      "SELECT id, name, interval, price_minor, currency, trial_days, grace_days, available, features_json, max_devices, max_staff FROM plans ORDER BY name"
    );

    if (result.rows.length === 0) {
      throw new Error("No subscription plans exist in Supabase. Import plans before starting the service.");
    }

    this.initializationStage = "plan_validation";
    this.plans = new Map(result.rows.map(row => [row.id, {
      id: row.id,
      name: row.name,
      interval: row.interval,
      priceMinor: Number(row.price_minor),
      currency: row.currency,
      trialDays: Number(row.trial_days),
      graceDays: Number(row.grace_days),
      available: row.available === true || Number(row.available) === 1,
      features: parseJsonValue(row.features_json, `Plan ${row.id} features`) ?? [],
      maxDevices: row.max_devices ?? null,
      maxStaff: row.max_staff ?? null
    }]));
    if (this.requireFixedGrace &&
        [...this.plans.values()].some(plan => plan.graceDays !== SUBSCRIPTION_GRACE_DAYS)) {
      throw new Error(`Every stored production plan must have a ${SUBSCRIPTION_GRACE_DAYS}-day subscription grace period.`);
    }

    this.initializationStage = "ready";
    return this.plans;
  }

  async log(event, options = {}) {
    return this.insertLog(event, options);
  }

  async healthCheck() {
    const result = await this.db.healthCheck();
    return { status: "ok", service: "shoppos-license-server", database: "postgresql", ...result };
  }

  async createAdminSession(sessionId, { adminId, csrfToken, expiresAt }) {
    assertText(adminId, "Administrator ID", 100);
    assertText(csrfToken, "CSRF token", 128);
    const expiry = new Date(expiresAt);
    if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= this.now()) {
      throw new Error("Administrator session expiry must be in the future.");
    }
    const sessionHash = crypto.createHash("sha256").update(assertText(sessionId, "Session ID", 128)).digest("hex");
    await this.db.transaction(async client => {
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["shoppos-admin-session-cap"]);
      await client.query("DELETE FROM admin_sessions WHERE expires_at <= NOW()");
      const count = await client.query("SELECT COUNT(*)::int AS count FROM admin_sessions");
      if (count.rows[0].count >= 10000) {
        throw Object.assign(new Error("The admin session limit has been reached. Try again later."), { statusCode: 503 });
      }
      await client.query(
        `INSERT INTO admin_sessions (session_hash, admin_id, csrf_token, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [sessionHash, adminId.trim(), csrfToken, expiry.toISOString(), new Date(this.now()).toISOString()]
      );
    });
  }

  async getAdminSession(sessionId) {
    if (typeof sessionId !== "string" || !sessionId) return undefined;
    const sessionHash = crypto.createHash("sha256").update(sessionId).digest("hex");
    const result = await this.db.query(
      `SELECT admin_id, csrf_token, expires_at
       FROM admin_sessions WHERE session_hash = $1 AND expires_at > NOW()`,
      [sessionHash]
    );
    const row = result.rows[0];
    if (!row) return undefined;
    return {
      adminId: row.admin_id,
      csrfToken: row.csrf_token,
      expiresAt: new Date(row.expires_at).getTime()
    };
  }

  async deleteAdminSession(sessionId) {
    if (typeof sessionId !== "string" || !sessionId) return;
    const sessionHash = crypto.createHash("sha256").update(sessionId).digest("hex");
    await this.db.query("DELETE FROM admin_sessions WHERE session_hash = $1", [sessionHash]);
  }

  async consumeRateLimit(bucket, identity, limit, windowMs) {
    if (!Number.isInteger(limit) || limit < 1 || !Number.isInteger(windowMs) || windowMs < 1) {
      throw new Error("Rate-limit settings must be positive integers.");
    }
    const keyHash = crypto.createHash("sha256")
      .update(`${assertText(bucket, "Rate-limit bucket", 80)}\0${assertText(identity, "Rate-limit identity", 256)}`)
      .digest("hex");
    const result = await this.db.query(
      `INSERT INTO request_rate_limits (key_hash, window_start, request_count)
       VALUES ($1, NOW(), 1)
       ON CONFLICT (key_hash) DO UPDATE SET
         request_count = CASE
           WHEN request_rate_limits.window_start <= NOW() - ($2 * INTERVAL '1 millisecond') THEN 1
           ELSE request_rate_limits.request_count + 1
         END,
         window_start = CASE
           WHEN request_rate_limits.window_start <= NOW() - ($2 * INTERVAL '1 millisecond') THEN NOW()
           ELSE request_rate_limits.window_start
         END
       RETURNING request_count`,
      [keyHash, windowMs]
    );
    return Number(result.rows[0].request_count) <= limit;
  }

  async resetRateLimit(bucket, identity) {
    const keyHash = crypto.createHash("sha256")
      .update(`${assertText(bucket, "Rate-limit bucket", 80)}\0${assertText(identity, "Rate-limit identity", 256)}`)
      .digest("hex");
    await this.db.query("DELETE FROM request_rate_limits WHERE key_hash = $1", [keyHash]);
  }

  async insertLog(event, {
    licenseId = null,
    actorId = null,
    localShopId = null,
    deviceId = null,
    remoteAddress = null,
    detail = ""
  } = {}, client = this.db) {
    await client.query(
      `INSERT INTO license_logs
       (license_id, actor_id, event, local_shop_id, device_id, remote_address, created_at, detail)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        licenseId,
        actorId,
        event,
        localShopId,
        deviceId,
        remoteAddress,
        new Date(this.now()).toISOString(),
        String(detail).slice(0, 300)
      ]
    );
  }

  async getLicense(licenseId, client = this.db, { forUpdate = false } = {}) {
    const result = await client.query(
      `SELECT licenses.*, shops.name AS shop_name
       FROM licenses
       JOIN shops ON shops.id = licenses.shop_id
       WHERE licenses.id = $1${forUpdate ? " FOR UPDATE OF licenses" : ""}`,
      [licenseId]
    );

    const row = result.rows[0];

    if (!row) throw new Error("License was not found.");

    const plan = this.plans.get(row.plan_id);

    if (!plan) {
      throw new Error("The license references a plan that is no longer configured.");
    }

    return { row, plan };
  }

  async view(licenseId) {
    const { row, plan } = await this.getLicense(licenseId);
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
      throw new Error("License token signature is invalid.");
    }

    return decoded.payload;
  }

  async createShop(input, { actorId } = {}) {
    const shopName = assertText(input.shopName, "Shop name", 120);
    const plan = this.plans.get(assertText(input.planId, "Plan ID", 40));

    if (!plan || !plan.available) {
      throw new Error("Choose an available configured subscription plan.");
    }

    const now = new Date(this.now()).toISOString();
    const shopId = crypto.randomUUID();
    const licenseId = crypto.randomUUID();
    const licenseKey = `SP-${crypto.randomBytes(24).toString("base64url")}`;
    const trialEndsAt = plan.trialDays
      ? new Date(this.now() + plan.trialDays * 86400000).toISOString()
      : null;
    const expiresAt = trialEndsAt ?? addPeriod(now, plan.interval);

    await this.db.transaction(async client => {
      await client.query(
        "INSERT INTO shops (id, name, created_at) VALUES ($1,$2,$3)",
        [shopId, shopName, now]
      );

      await client.query(
        `INSERT INTO licenses
         (id, shop_id, key_hash, plan_id, state, starts_at, expires_at,
          trial_ends_at, created_at, updated_at)
         VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9)`,
        [
          licenseId, shopId,
          crypto.createHash("sha256").update(licenseKey).digest("hex"),
          plan.id, now, expiresAt, trialEndsAt, now, now
        ]
      );

      await this.insertLog("license_created", { licenseId, actorId }, client);
    });

    return { ...await this.view(licenseId), licenseKey };
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
      await this.db.transaction(async client => {
        await client.query(
          `INSERT INTO shops
           (id, name, local_shop_id, verified_by, verified_at, created_at)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [serverShopId, name, shopId, actorId ?? null, now, now]
        );

        await this.insertLog("shop_registered", {
          actorId,
          localShopId: shopId,
          detail: "admin_attested_existing_shop"
        }, client);
      });
    } catch (error) {
      if (error.code === "23505") {
        throw new Error("That ShopPOS Shop ID is already registered.");
      }
      throw error;
    }

    return this.getShop(serverShopId);
  }

  async getShop(shopId) {
    const result = await this.db.query(
      `SELECT s.id, s.name, s.local_shop_id AS "localShopId",
       s.verified_by AS "verifiedBy", s.verified_at AS "verifiedAt",
       s.created_at AS "createdAt", COUNT(l.id)::int AS "licenseCount"
       FROM shops s
       LEFT JOIN licenses l ON l.shop_id = s.id
       WHERE s.id = $1
       GROUP BY s.id`,
      [shopId]
    );

    return result.rows[0] ?? null;
  }

  async listShops() {
    const result = await this.db.query(
      `SELECT s.id, s.name, s.local_shop_id AS "localShopId",
       s.verified_by AS "verifiedBy", s.verified_at AS "verifiedAt",
       s.created_at AS "createdAt",
       COUNT(l.id)::int AS "licenseCount",
       MAX(l.created_at) AS "latestLicenseCreatedAt"
       FROM shops s
       LEFT JOIN licenses l ON l.shop_id = s.id
       GROUP BY s.id
       ORDER BY s.created_at DESC`
    );

    return result.rows;
  }

  async createLicenseForShop(shopId, input, { actorId } = {}) {
    const shop = await this.getShop(assertShopId(shopId, "Server Shop ID"));

    if (!shop) throw new Error("Registered server shop was not found.");
    if (!shop.localShopId) {
      throw new Error("Register and verify the ShopPOS Shop ID before issuing a bound license.");
    }

    if (assertShopId(input.confirmedLocalShopId, "Confirmation Shop ID") !== shop.localShopId) {
      throw new Error("Confirm the exact registered ShopPOS Shop ID before issuing a license.");
    }

    const plan = this.plans.get(assertText(input.planId, "Plan ID", 40));

    if (!plan || !plan.available) {
      throw new Error("Choose an available configured subscription plan.");
    }

    const nowValue = this.now();
    const now = new Date(nowValue).toISOString();
    let expiresAt;
    let trialEndsAt = null;

    if (input.expiresAt !== undefined && input.expiresAt !== null && input.expiresAt !== "") {
      if (
        typeof input.expiresAt !== "string" ||
        !Number.isFinite(Date.parse(input.expiresAt)) ||
        new Date(Date.parse(input.expiresAt)).toISOString() !== input.expiresAt ||
        Date.parse(input.expiresAt) <= nowValue
      ) {
        throw new Error("A custom license expiration must be a future ISO timestamp.");
      }
      expiresAt = input.expiresAt;
    } else {
      trialEndsAt = plan.trialDays
        ? new Date(nowValue + plan.trialDays * 86400000).toISOString()
        : null;
      expiresAt = trialEndsAt ?? addPeriod(now, plan.interval);
    }

    const licenseId = crypto.randomUUID();
    const licenseKey = `SP-${crypto.randomBytes(24).toString("base64url")}`;

    await this.db.transaction(async client => {
      await client.query(
        `INSERT INTO licenses
         (id, shop_id, key_hash, plan_id, state, starts_at, expires_at,
          trial_ends_at, intended_local_shop_id, created_at, updated_at)
         VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10)`,
        [
          licenseId, shop.id,
          crypto.createHash("sha256").update(licenseKey).digest("hex"),
          plan.id, now, expiresAt, trialEndsAt, shop.localShopId, now, now
        ]
      );

      await this.insertLog("license_created", {
        licenseId,
        actorId,
        localShopId: shop.localShopId,
        detail: input.expiresAt ? "custom_expiration" : "configured_plan_term"
      }, client);
    });

    return { ...await this.view(licenseId), licenseKey };
  }

  async updatePlan(input, { actorId } = {}) {
    const plan = [...parsePlans([input]).values()][0];
    plan.graceDays = SUBSCRIPTION_GRACE_DAYS;

    const maxDevices = input.maxDevices === undefined || input.maxDevices === "" || input.maxDevices === null
      ? null : Number(input.maxDevices);

    const maxStaff = input.maxStaff === undefined || input.maxStaff === "" || input.maxStaff === null
      ? null : Number(input.maxStaff);

    if (
      (maxDevices !== null && (!Number.isSafeInteger(maxDevices) || maxDevices < 0)) ||
      (maxStaff !== null && (!Number.isSafeInteger(maxStaff) || maxStaff < 0))
    ) {
      throw new Error("Plan device and staff limits must be non-negative integers.");
    }

    const featuresJson = JSON.stringify(input.features
      ? String(input.features).slice(0, 300).split(/[;,\n]/).map(item => item.trim()).filter(Boolean)
      : []);

    const now = new Date(this.now()).toISOString();

    await this.db.transaction(async client => {
      await client.query(
        `INSERT INTO plans
         (id, name, interval, price_minor, currency, trial_days, grace_days,
          available, features_json, max_devices, max_staff, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         interval = EXCLUDED.interval,
         price_minor = EXCLUDED.price_minor,
         currency = EXCLUDED.currency,
         trial_days = EXCLUDED.trial_days,
         grace_days = EXCLUDED.grace_days,
         available = EXCLUDED.available,
         features_json = EXCLUDED.features_json,
         max_devices = EXCLUDED.max_devices,
         max_staff = EXCLUDED.max_staff,
         updated_at = EXCLUDED.updated_at`,
        [
          plan.id, plan.name, plan.interval, plan.priceMinor, plan.currency,
          plan.trialDays, plan.graceDays, plan.available,
          featuresJson, maxDevices, maxStaff, now
        ]
      );
      await this.insertLog("plan_updated", { actorId, detail: plan.id }, client);
    });

    await this.initialize();

    return { ...this.plans.get(plan.id) };
  }

  listPlans() {
    return [...this.plans.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  async list() {
    const result = await this.db.query(
      `SELECT licenses.*, shops.name AS shop_name
       FROM licenses JOIN shops ON shops.id = licenses.shop_id
       ORDER BY licenses.created_at DESC`
    );
    return result.rows.map(row => licenseView(row, this.plans.get(row.plan_id), this.now()));
  }

  async logs(licenseId) {
    const result = await this.db.query(
      `SELECT id, license_id AS "licenseId", actor_id AS "actorId", event,
       local_shop_id AS "localShopId", device_id AS "deviceId",
       remote_address AS "remoteAddress", created_at AS "createdAt", detail
       FROM license_logs
       ${licenseId ? "WHERE license_id = $1" : ""}
       ORDER BY id DESC LIMIT 500`,
      licenseId ? [licenseId] : []
    );
    return result.rows;
  }

  async activate({ licenseKey, localShopId, deviceId, remoteAddress }) {
    const key = assertText(licenseKey, "License key", 100);
    const shopId = assertShopId(localShopId, "Local Shop ID");
    const device = assertText(deviceId, "Device ID", 200);
    const keyHash = crypto.createHash("sha256").update(key).digest("hex");

    return this.db.transaction(async client => {
      const result = await client.query(
        `SELECT licenses.*, shops.name AS shop_name
         FROM licenses JOIN shops ON shops.id = licenses.shop_id
         WHERE licenses.key_hash = $1 FOR UPDATE OF licenses`,
        [keyHash]
      );

      const row = result.rows[0];
      if (!row) throw new Error("License key is invalid.");

      const plan = this.plans.get(row.plan_id);
      if (!plan) throw new Error("License plan is unavailable.");

      if (row.key_redeemed_at) throw new Error("This activation key has already been redeemed.");

      if (row.state !== "active") {
        throw new Error(`License is ${row.state}.`);
      }

      const currentStatus = statusFor(row, plan, this.now());
      if (currentStatus === "expired") {
        throw new Error("This license is expired.");
      }

      if (row.intended_local_shop_id && row.intended_local_shop_id !== shopId) {
        throw new Error("This license was issued for a different ShopPOS shop.");
      }

      if ((row.local_shop_id && row.local_shop_id !== shopId) ||
          (row.device_id && row.device_id !== device)) {
        throw new Error("This license is already bound to another shop installation.");
      }

      const now = new Date(this.now()).toISOString();

      const update = await client.query(
        `UPDATE licenses SET local_shop_id=$1, device_id=$2,
         activated_at=COALESCE(activated_at,$3),
         key_redeemed_at=$3,
         updated_at=$3 WHERE id=$4 AND key_redeemed_at IS NULL`,
        [shopId, device, now, row.id]
      );

      if (update.rowCount !== 1) {
        throw new Error("This activation key has already been redeemed.");
      }

      await this.insertLog("activation_succeeded", {
        licenseId: row.id,
        actorId: "licensee",
        localShopId: shopId,
        deviceId: device,
        remoteAddress
      }, client);

      const updated = await this.getLicense(row.id, client);
      return {
        token: this.sign(updated.row, updated.plan, shopId, device),
        status: licenseView(updated.row, updated.plan, this.now())
      };
    });
  }

  async status({ token, localShopId, deviceId, remoteAddress }) {
    const payload = this.verify(token);
    const shopId = assertShopId(localShopId, "Local Shop ID");
    const device = assertText(deviceId, "Device ID", 200);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }

    const { row, plan } = await this.getLicense(payload.licenseId);

    if (row.shop_id !== payload.shopId || row.local_shop_id !== shopId || row.device_id !== device) {
      throw new Error("This license is no longer activated for this shop installation.");
    }

    const status = statusFor(row, plan, this.now());
    const refreshedToken = this.sign(row, plan, shopId, device);
    await this.insertLog("status_check", {
      licenseId: row.id,
      localShopId: shopId,
      deviceId: device,
      remoteAddress,
      detail: status
    });

    return {
      token: refreshedToken,
      status: licenseView(row, plan, this.now())
    };
  }

  async deactivate({ token, localShopId, deviceId, remoteAddress }) {
    const payload = this.verify(token);
    const shopId = assertShopId(localShopId, "Local Shop ID");
    const device = assertText(deviceId, "Device ID", 200);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }

    return this.db.transaction(async client => {
      const result = await client.query(
        "SELECT * FROM licenses WHERE id=$1 FOR UPDATE",
        [payload.licenseId]
      );

      const row = result.rows[0];
      if (!row) throw new Error("License was not found.");

      if (row.local_shop_id !== shopId || row.device_id !== device) {
        throw new Error("License activation does not match this device.");
      }

      const now = new Date(this.now()).toISOString();

      const update = await client.query(
        `UPDATE licenses SET local_shop_id=NULL, device_id=NULL,
         activated_at=NULL, updated_at=$1 WHERE id=$2 AND local_shop_id=$3 AND device_id=$4`,
        [now, payload.licenseId, shopId, device]
      );
      if (update.rowCount !== 1) throw new Error("This license is no longer activated for this installation.");

      await this.insertLog("deactivation", {
        licenseId: payload.licenseId,
        actorId: "licensee",
        localShopId: shopId,
        deviceId: device,
        remoteAddress
      }, client);

      return { deactivated: true };
    });
  }

  renewalExpiry(row, plan) {
    const nowValue = this.now();
    const anchor = Math.max(nowValue, Date.parse(row.expires_at));
    let expiresAt = addPeriod(new Date(anchor).toISOString(), plan.interval);
    if (Date.parse(expiresAt) <= nowValue) {
      expiresAt = addPeriod(new Date(nowValue).toISOString(), plan.interval);
    }
    return { anchor, expiresAt };
  }

  async applyRenewal(licenseId, planId, { actorId = null, paymentId = null, client = this.db } = {}) {
    const { row, plan } = await this.getLicense(licenseId, client, { forUpdate: true });
    if (plan.id !== planId) throw new Error("The payment plan no longer matches the license plan.");
    if (row.state !== "active") {
      throw new Error("Only an active license can be renewed. Reactivate a suspended license first.");
    }

    const { expiresAt } = this.renewalExpiry(row, plan);
    const now = new Date(this.now()).toISOString();
    const update = await client.query(
      `UPDATE licenses SET expires_at=$1, trial_ends_at=NULL, updated_at=$2
       WHERE id=$3 AND state='active'`,
      [expiresAt, now, licenseId]
    );
    if (update.rowCount !== 1) {
      throw new Error(paymentId
        ? "The payment was already applied, or the license is no longer active."
        : "The license is no longer active.");
    }

    await this.insertLog("renewal", {
      licenseId,
      actorId,
      detail: paymentId ? `payment:${paymentId}` : "admin_manual"
    }, client);

    const updated = await this.getLicense(licenseId, client);
    return licenseView(updated.row, updated.plan, this.now());
  }

  async renew(licenseId, { actorId } = {}) {
    return this.db.transaction(async client => {
      const { plan } = await this.getLicense(licenseId, client, { forUpdate: true });
      return this.applyRenewal(licenseId, plan.id, { actorId, client });
    });
  }

  async submitManualPayment({
    token, localShopId, deviceId, planId, amountMinor, currency, reference, note
  }, { remoteAddress } = {}) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }

    try {
      const paymentId = await this.db.transaction(async client => {
        const result = await client.query(
          `SELECT licenses.*, shops.name AS shop_name
           FROM licenses JOIN shops ON shops.id=licenses.shop_id
           WHERE licenses.id=$1 FOR UPDATE OF licenses`,
          [payload.licenseId]
        );
        const row = result.rows[0];
        if (!row || row.shop_id !== payload.shopId) {
          throw new Error("The licensed shop was not found.");
        }
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
        const normalizedReference = assertText(reference, "Payment reference", 120);
        if (normalizedReference.length < 4) {
          throw new Error("The payment reference must be at least 4 characters.");
        }

        const now = new Date(this.now()).toISOString();
        const id = crypto.randomUUID();
        await client.query(
          `INSERT INTO payments
           (id, shop_id, license_id, plan_id, method, status, amount_minor, currency,
            reference, reference_key, note, submitted_by_device, submitted_at, created_at, updated_at)
           VALUES ($1,$2,$3,$4,'manual','pending',$5,$6,$7,$8,$9,$10,$11,$11,$11)`,
          [
            id, row.shop_id, row.id, plan.id, amountMinor, currency,
            normalizedReference, `manual:${row.id}:${normalizedReference.toLowerCase()}`,
            note ? String(note).slice(0, 300) : null, device, now
          ]
        );
        await this.insertLog("payment_submitted", {
          licenseId: row.id,
          actorId: "licensee",
          localShopId: shopId,
          deviceId: device,
          remoteAddress,
          detail: `manual:${id}`
        }, client);
        await this.insertPaymentEvent(id, "submitted", {
          actorId: "licensee",
          remoteAddress,
          detail: `reference:${normalizedReference}`
        }, client);
        return id;
      });
      return this.paymentView(paymentId);
    } catch (error) {
      if (error.code === "23505" && error.constraint === "payments_reference_key_key") {
        throw new Error("This payment reference has already been submitted for this subscription.");
      }
      if (error.code === "23505" && error.constraint === "idx_payments_provider_txn") {
        throw new Error("This transaction id is already recorded.");
      }
      throw error;
    }
  }

  async paymentView(id, client = this.db) {
    const result = await client.query(
      `SELECT payments.*, shops.name AS shop_name
       FROM payments JOIN shops ON shops.id=payments.shop_id WHERE payments.id=$1`,
      [id]
    );
    const row = result.rows[0];
    if (!row) throw new Error("Payment was not found.");
    return {
      id: row.id,
      shopId: row.shop_id,
      shopName: row.shop_name,
      licenseId: row.license_id,
      planId: row.plan_id,
      method: row.method,
      status: row.status,
      amountMinor: Number(row.amount_minor),
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
    const boundedLimit = Math.min(Math.max(1, Number(limit) || 500), 500);
    const result = await this.db.query(
      `SELECT payments.*, shops.name AS shop_name FROM payments
       JOIN shops ON shops.id=payments.shop_id
       ${safeStatus ? "WHERE payments.status=$1" : ""}
       ORDER BY payments.submitted_at DESC LIMIT $${safeStatus ? 2 : 1}`,
      safeStatus ? [safeStatus, boundedLimit] : [boundedLimit]
    );
    return result.rows.map(row => ({
      id: row.id,
      shopId: row.shop_id,
      shopName: row.shop_name,
      licenseId: row.license_id,
      planId: row.plan_id,
      method: row.method,
      status: row.status,
      amountMinor: Number(row.amount_minor),
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

  async licenseePayments({ token, localShopId, deviceId, limit = 50 }) {
    const payload = this.verify(token);
    const shopId = assertText(localShopId, "Local shop ID", 80);
    const device = assertText(deviceId, "Installation ID", 80);
    if (payload.localShopId !== shopId || payload.deviceId !== device) {
      throw new Error("This license belongs to a different shop installation.");
    }
    const { row } = await this.getLicense(payload.licenseId);
    if (row.shop_id !== payload.shopId || row.local_shop_id !== shopId || row.device_id !== device) {
      throw new Error("This license is no longer activated for this shop installation.");
    }
    const boundedLimit = Math.min(Math.max(1, Number(limit) || 50), 100);
    const result = await this.db.query(
      `SELECT id, plan_id, method, status, amount_minor, currency, reference,
       provider, provider_transaction_id, submitted_at, decided_at, decision_reason, applied_at
       FROM payments WHERE license_id=$1 ORDER BY submitted_at DESC LIMIT $2`,
      [row.id, boundedLimit]
    );
    return result.rows.map(item => ({
      id: item.id,
      planId: item.plan_id,
      method: item.method,
      status: item.status,
      amountMinor: Number(item.amount_minor),
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
    const result = await this.db.transaction(async client => {
      const paymentResult = await client.query(
        "SELECT * FROM payments WHERE id=$1 FOR UPDATE",
        [paymentId]
      );
      const payment = paymentResult.rows[0];
      if (!payment) throw new Error("Payment was not found.");
      if (payment.status !== "pending") {
        throw new Error("An already decided payment cannot be approved again.");
      }

      const { plan } = await this.getLicense(payment.license_id, client);
      if (!plan || !plan.available) {
        throw new Error("The payment references a plan that is no longer available.");
      }
      if (payment.currency !== plan.currency || Number(payment.amount_minor) !== plan.priceMinor) {
        throw new Error("The submitted amount or currency no longer matches the plan price. Reject it with a reason instead.");
      }

      const now = new Date(this.now()).toISOString();
      const update = await client.query(
        `UPDATE payments SET status='approved', decided_by=$1, decided_at=$2, updated_at=$2
         WHERE id=$3 AND status='pending'`,
        [actorId ?? null, now, paymentId]
      );
      if (update.rowCount !== 1) {
        throw new Error("An already decided payment cannot be approved again.");
      }

      const license = await this.applyRenewal(payment.license_id, payment.plan_id, {
        actorId,
        paymentId,
        client
      });
      await client.query(
        "UPDATE payments SET applied_at=$1, updated_at=$1 WHERE id=$2",
        [now, paymentId]
      );
      await this.insertPaymentEvent(paymentId, "approved", {
        actorId: actorId ?? null,
        remoteAddress,
        detail: `renewed_license:${payment.license_id}`
      }, client);
      return license;
    });

    return { payment: await this.paymentView(paymentId), license: result };
  }

  async rejectPayment(paymentId, { actorId, reason, remoteAddress } = {}) {
    const rejectionReason = assertText(reason ?? "", "Rejection reason", 300);
    if (rejectionReason.length < 3) {
      throw new Error("A rejection reason of at least 3 characters is required.");
    }
    await this.db.transaction(async client => {
      const payment = await client.query(
        "SELECT id, status FROM payments WHERE id=$1 FOR UPDATE",
        [paymentId]
      );
      if (!payment.rows[0]) throw new Error("Payment was not found.");
      if (payment.rows[0].status !== "pending") {
        throw new Error("An already decided payment cannot be rejected again.");
      }

      const now = new Date(this.now()).toISOString();
      const update = await client.query(
        `UPDATE payments SET status='rejected', decided_by=$1, decided_at=$2,
         decision_reason=$3, updated_at=$2 WHERE id=$4 AND status='pending'`,
        [actorId ?? null, now, rejectionReason, paymentId]
      );
      if (update.rowCount !== 1) {
        throw new Error("An already decided payment cannot be rejected again.");
      }
      await this.insertPaymentEvent(paymentId, "rejected", {
        actorId: actorId ?? null,
        remoteAddress,
        detail: rejectionReason
      }, client);
    });
    return this.paymentView(paymentId);
  }

  async recordGatewayEvent(provider, normalized, { remoteAddress } = {}) {
    const now = new Date(this.now()).toISOString();
    return this.db.transaction(async client => {
      const inserted = await client.query(
        `INSERT INTO gateway_events
         (provider, event_id, event_type, provider_transaction_id, remote_address, result, received_at)
         VALUES ($1,$2,$3,$4,$5,'received',$6)
         ON CONFLICT (provider, event_id) DO NOTHING
         RETURNING event_id`,
        [provider, normalized.eventId, normalized.eventType, normalized.transactionId, remoteAddress ?? null, now]
      );
      if (inserted.rowCount === 0) return { duplicate: true, applied: false };

      const successful = normalized.status === "succeeded";
      const nextStatus = successful
        ? "approved"
        : PAYMENT_STATUSES.has(normalized.status) ? normalized.status : null;
      if (!nextStatus) {
        await this.insertPaymentEvent(null, "gateway_unmatched", {
          remoteAddress,
          detail: `${provider}:${normalized.eventId}:unknown status`
        }, client);
        await client.query(
          `UPDATE gateway_events SET result='recorded'
           WHERE provider=$1 AND event_id=$2`,
          [provider, normalized.eventId]
        );
        return { duplicate: false, applied: false };
      }

      const paymentResult = await client.query(
        `SELECT * FROM payments
         WHERE lower(reference)=lower($1) AND status='pending'
         ORDER BY submitted_at DESC LIMIT 1 FOR UPDATE`,
        [normalized.customerReference ?? ""]
      );
      const payment = paymentResult.rows[0];
      let applied = false;
      let paymentId = null;

      if (!payment) {
        await this.insertPaymentEvent(null, "gateway_unmatched", {
          remoteAddress,
          detail: `${provider}:${normalized.eventId}:${normalized.transactionId}`
        }, client);
      } else {
        paymentId = payment.id;
        if (successful) {
          if (Number(payment.amount_minor) !== normalized.amountMinor ||
              payment.currency !== normalized.currency) {
            await this.insertPaymentEvent(paymentId, "gateway_amount_mismatch", {
              remoteAddress,
              detail: `expected:${payment.currency}${payment.amount_minor} received:${normalized.currency}${normalized.amountMinor}`
            }, client);
          } else {
            const update = await client.query(
              `UPDATE payments SET status='approved', method='gateway', provider=$1,
               provider_transaction_id=$2, decided_by='gateway', decided_at=$3, updated_at=$3
               WHERE id=$4 AND status='pending'`,
              [provider, normalized.transactionId, now, paymentId]
            );
            if (update.rowCount === 1) {
              const license = await this.applyRenewal(payment.license_id, payment.plan_id, {
                actorId: `gateway:${provider}`,
                paymentId,
                client
              });
              await client.query(
                "UPDATE payments SET applied_at=$1, updated_at=$1 WHERE id=$2",
                [now, paymentId]
              );
              await this.insertPaymentEvent(paymentId, "approved", {
                actorId: "gateway",
                remoteAddress,
                detail: `renewed_license:${payment.license_id} term:${license.expiresAt}`
              }, client);
              applied = true;
            }
          }
        } else {
          const update = await client.query(
            `UPDATE payments SET status=$1, decided_by='gateway', decided_at=$2, updated_at=$2
             WHERE id=$3 AND status='pending'`,
            [nextStatus, now, paymentId]
          );
          if (update.rowCount === 1) {
            await this.insertPaymentEvent(paymentId, `gateway_${nextStatus}`, {
              actorId: "gateway",
              remoteAddress,
              detail: `${provider}:${normalized.eventId}`
            }, client);
          }
        }
      }

      await client.query(
        `UPDATE gateway_events SET payment_id=$1, result=$2
         WHERE provider=$3 AND event_id=$4`,
        [paymentId, applied ? "applied" : "recorded", provider, normalized.eventId]
      );
      return { duplicate: false, applied };
    });
  }

  async insertPaymentEvent(paymentId, event, {
    actorId = null, remoteAddress = null, detail = ""
  } = {}, client = this.db) {
    await client.query(
      `INSERT INTO payment_events
       (payment_id, event, actor_id, remote_address, detail, created_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [paymentId, event, actorId, remoteAddress, String(detail).slice(0, 300), new Date(this.now()).toISOString()]
    );
  }

  async changeState(licenseId, state, { actorId } = {}) {
    if (!["suspended", "reactivated", "cancelled", "revoked"].includes(state)) {
      throw new Error("Unsupported license state.");
    }
    await this.db.transaction(async client => {
      const { row } = await this.getLicense(licenseId, client, { forUpdate: true });
      if (row.state === "revoked" ||
          (row.state === "cancelled" && state !== "revoked")) {
        throw new Error("A cancelled or revoked license cannot be reactivated.");
      }
      if (state === "reactivated" && row.state !== "suspended") {
        throw new Error("Only a suspended license can be reactivated.");
      }
      const nextState = state === "reactivated" ? "active" : state;
      const now = new Date(this.now()).toISOString();
      const update = await client.query(
        "UPDATE licenses SET state=$1, updated_at=$2 WHERE id=$3",
        [nextState, now, row.id]
      );
      if (update.rowCount !== 1) throw new Error("The license could not be updated.");
      await this.insertLog(state, { licenseId: row.id, actorId }, client);
    });
    return this.view(licenseId);
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
    const result = await this.db.query(
      `SELECT payments.currency,
       ROUND(SUM(CASE WHEN plans.interval='yearly'
         THEN payments.amount_minor / 12.0 ELSE payments.amount_minor END))::bigint AS amount_minor
       FROM payments JOIN plans ON plans.id=payments.plan_id
       WHERE payments.status='approved' AND payments.applied_at >= $1 AND payments.applied_at < $2
       GROUP BY payments.currency`,
      [periodStart.toISOString(), new Date(this.now()).toISOString()]
    );
    const currencies = Object.fromEntries(result.rows.map(row => [row.currency, Number(row.amount_minor)]));
    return { period: { start: periodStart.toISOString() }, currencies };
  }

  async paymentLogs(limit = 200) {
    const boundedLimit = Math.min(Math.max(1, Number(limit) || 200), 500);
    const result = await this.db.query(
      `SELECT id, payment_id AS "paymentId", event, actor_id AS "actorId",
       remote_address AS "remoteAddress", detail, created_at AS "createdAt"
       FROM payment_events ORDER BY id DESC LIMIT $1`,
      [boundedLimit]
    );
    return result.rows;
  }

  async createBackup() {
    throw Object.assign(
      new Error("PostgreSQL backups must be created and restored with Supabase-managed backups or pg_dump. Serverless local-file backups are unavailable."),
      { statusCode: 501 }
    );
  }

  async verifyBackup() {
    throw Object.assign(
      new Error("PostgreSQL backup verification must use Supabase tooling or pg_restore --list against an exported backup."),
      { statusCode: 501 }
    );
  }

  async restoreFromBackup() {
    throw Object.assign(
      new Error("PostgreSQL restore must be performed through an approved Supabase recovery or pg_restore procedure, not the application API."),
      { statusCode: 501 }
    );
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    await this.db.close();
  }
}

module.exports = {
  PostgresLicenseService,
  parsePlans,
  statusFor,
  licenseView,
  addPeriod,
  assertText,
  assertShopId,
  PAYMENT_STATUSES,
  SUBSCRIPTION_GRACE_DAYS
};
