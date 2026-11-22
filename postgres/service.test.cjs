"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const tls = require("node:tls");
const { Client } = require("pg");
const { PostgresLicenseService } = require("./service.cjs");
const { validatePostgresConfiguration } = require("./server.cjs");
const {
  classifyPostgresError,
  createPoolConfig,
  decodeCaCertificate,
  getPostgresErrorDiagnostic
} = require("./database.cjs");
const { createLicenseServer } = require("../license-server.cjs");
const { verifySignedToken } = require("../../desktop/license.cjs");

const now = Date.parse("2026-01-15T12:00:00.000Z");
const shopId = "13814000-1dd2-11b2-8000-000000000001";
const deviceId = "13814000-1dd2-11b2-8000-000000000003";
const plans = [{
  id: "monthly",
  name: "Monthly",
  interval: "monthly",
  priceMinor: 4200,
  currency: "USD",
  trialDays: 0,
  graceDays: 7
}];
const planRow = {
  id: "monthly",
  name: "Monthly",
  interval: "monthly",
  price_minor: 4200,
  currency: "USD",
  trial_days: 0,
  grace_days: 7,
  available: true,
  features_json: "[]",
  max_devices: null,
  max_staff: null
};
const requiredTables = [
  "shops", "plans", "licenses", "license_logs", "payments", "payment_events", "gateway_events"
];
const requiredColumns = {
  shops: ["id", "name", "local_shop_id", "verified_by", "verified_at", "created_at"],
  plans: ["id", "name", "interval", "price_minor", "currency", "trial_days", "grace_days", "available", "features_json", "max_devices", "max_staff", "updated_at"],
  licenses: ["id", "shop_id", "key_hash", "plan_id", "state", "starts_at", "expires_at", "trial_ends_at", "intended_local_shop_id", "key_redeemed_at", "local_shop_id", "device_id", "activated_at", "created_at", "updated_at"],
  license_logs: ["id", "license_id", "actor_id", "event", "local_shop_id", "device_id", "remote_address", "created_at", "detail"],
  payments: ["id", "shop_id", "license_id", "plan_id", "method", "status", "amount_minor", "currency", "reference", "reference_key", "provider", "provider_transaction_id", "note", "decision_reason", "submitted_by_device", "submitted_at", "decided_by", "decided_at", "applied_at", "created_at", "updated_at"],
  payment_events: ["id", "payment_id", "event", "actor_id", "remote_address", "detail", "created_at"],
  gateway_events: ["provider", "event_id", "event_type", "provider_transaction_id", "payment_id", "result", "remote_address", "received_at"]
};

class FakeDatabase {
  constructor() {
    this.shops = new Map();
    this.licenses = new Map();
    this.payments = new Map();
    this.logs = [];
    this.paymentEvents = [];
    this.gatewayEvents = new Map();
    this.rateLimits = new Map();
    this.adminSessions = new Map();
    this.planRows = [structuredClone(planRow)];
    this.planInsertCount = 0;
    this.lockedQueries = [];
  }

  async transaction(callback) {
    const snapshot = structuredClone({
      shops: this.shops,
      licenses: this.licenses,
      payments: this.payments,
      logs: this.logs,
      paymentEvents: this.paymentEvents,
      gatewayEvents: this.gatewayEvents,
      adminSessions: this.adminSessions
    });
    try {
      return await callback(this);
    } catch (error) {
      Object.assign(this, snapshot);
      throw error;
    }
  }

  shopRow(id) {
    return this.shops.get(id);
  }

  licenseRow(row) {
    if (!row) return undefined;
    return { ...row, shop_name: this.shops.get(row.shop_id)?.name };
  }

  async query(statement, values = []) {
    const sql = statement.replace(/\s+/g, " ").trim().toLowerCase();
    if (sql.startsWith("select table_name, column_name from information_schema.columns")) {
      return {
        rows: Object.entries(requiredColumns).flatMap(([table_name, columns]) =>
          columns.map(column_name => ({ table_name, column_name }))
        )
      };
    }
    if (sql.startsWith("select table_name from information_schema.tables")) {
      return { rows: requiredTables.map(table_name => ({ table_name })) };
    }
    if (sql.startsWith("create table if not exists")) return { rows: [], rowCount: 0 };
    if (sql.startsWith("delete from request_rate_limits where window_start")) return { rows: [], rowCount: 0 };
    if (sql === "select id from plans limit 1") {
      return { rows: this.planRows.length ? [{ id: this.planRows[0].id }] : [], rowCount: this.planRows.length ? 1 : 0 };
    }
    if (sql.startsWith("select id, name, interval, price_minor")) {
      return { rows: structuredClone(this.planRows), rowCount: this.planRows.length };
    }
    if (sql.startsWith("select pg_advisory_xact_lock")) return { rows: [], rowCount: 1 };
    if (sql.startsWith("select count(*)::int as count from admin_sessions")) {
      return { rows: [{ count: this.adminSessions.size }], rowCount: 1 };
    }

    if (sql.startsWith("insert into shops")) {
      const row = sql.includes("local_shop_id")
        ? {
            id: values[0], name: values[1], local_shop_id: values[2],
            verified_by: values[3], verified_at: values[4], created_at: values[5]
          }
        : { id: values[0], name: values[1], created_at: values[2] };
      if ([...this.shops.values()].some(shop => shop.local_shop_id && shop.local_shop_id === row.local_shop_id)) {
        throw Object.assign(new Error("duplicate key"), { code: "23505" });
      }
      this.shops.set(row.id, row);
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("insert into licenses")) {
      const row = sql.includes("intended_local_shop_id")
        ? {
            id: values[0], shop_id: values[1], key_hash: values[2], plan_id: values[3],
            state: "active", starts_at: values[4], expires_at: values[5],
            trial_ends_at: values[6], intended_local_shop_id: values[7],
            created_at: values[8], updated_at: values[9]
          }
        : {
            id: values[0], shop_id: values[1], key_hash: values[2], plan_id: values[3],
            state: "active", starts_at: values[4], expires_at: values[5],
            trial_ends_at: values[6], created_at: values[7], updated_at: values[8]
          };
      this.licenses.set(row.id, row);
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("insert into license_logs")) {
      this.logs.push({ license_id: values[0], actor_id: values[1], event: values[2], detail: values[7] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("select s.id, s.name, s.local_shop_id")) {
      const row = this.shops.get(values[0]);
      if (!row) return { rows: [], rowCount: 0 };
      const count = [...this.licenses.values()].filter(license => license.shop_id === row.id).length;
      return {
        rows: [{
          id: row.id,
          name: row.name,
          localShopId: row.local_shop_id ?? null,
          verifiedBy: row.verified_by ?? null,
          verifiedAt: row.verified_at ?? null,
          createdAt: row.created_at,
          licenseCount: count
        }],
        rowCount: 1
      };
    }
    if (sql.startsWith("select licenses.*, shops.name as shop_name")) {
      if (sql.includes("for update")) this.lockedQueries.push(sql);
      let row;
      if (sql.includes("where licenses.key_hash")) {
        row = [...this.licenses.values()].find(license => license.key_hash === values[0]);
      } else {
        row = this.licenses.get(values[0]);
      }
      return { rows: row ? [this.licenseRow(row)] : [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("select * from licenses where id=")) {
      const row = this.licenses.get(values[0]);
      if (sql.includes("for update")) this.lockedQueries.push(sql);
      return { rows: row ? [{ ...row }] : [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("update licenses set local_shop_id=$1")) {
      const row = [...this.licenses.values()].find(item => item.id === values[3] && !item.key_redeemed_at);
      if (!row) return { rows: [], rowCount: 0 };
      Object.assign(row, {
        local_shop_id: values[0],
        device_id: values[1],
        activated_at: row.activated_at ?? values[2],
        key_redeemed_at: values[2],
        updated_at: values[2]
      });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("update licenses set local_shop_id=null")) {
      const row = this.licenses.get(values[1]);
      if (!row || row.local_shop_id !== values[2] || row.device_id !== values[3]) return { rows: [], rowCount: 0 };
      Object.assign(row, { local_shop_id: null, device_id: null, activated_at: null, updated_at: values[0] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("update licenses set expires_at=$1")) {
      const row = this.licenses.get(values[2]);
      if (!row || row.state !== "active") return { rows: [], rowCount: 0 };
      Object.assign(row, { expires_at: values[0], trial_ends_at: null, updated_at: values[1] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("update licenses set state=$1")) {
      const row = this.licenses.get(values[2]);
      if (!row) return { rows: [], rowCount: 0 };
      Object.assign(row, { state: values[0], updated_at: values[1] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("insert into payments")) {
      const row = {
        id: values[0], shop_id: values[1], license_id: values[2], plan_id: values[3],
        method: "manual", status: "pending", amount_minor: values[4], currency: values[5],
        reference: values[6], reference_key: values[7], note: values[8],
        submitted_by_device: values[9], submitted_at: values[10], created_at: values[10], updated_at: values[10]
      };
      if ([...this.payments.values()].some(payment => payment.reference_key === row.reference_key)) {
        throw Object.assign(new Error("duplicate key"), { code: "23505", constraint: "payments_reference_key_key" });
      }
      this.payments.set(row.id, row);
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("select * from payments where id=")) {
      const row = this.payments.get(values[0]);
      if (sql.includes("for update")) this.lockedQueries.push(sql);
      return { rows: row ? [{ ...row }] : [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("select id, status from payments where id=")) {
      const row = this.payments.get(values[0]);
      if (sql.includes("for update")) this.lockedQueries.push(sql);
      return { rows: row ? [{ id: row.id, status: row.status }] : [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("select payments.*, shops.name as shop_name")) {
      const row = this.payments.get(values[0]);
      return { rows: row ? [{ ...row, shop_name: this.shops.get(row.shop_id)?.name }] : [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("update payments set status='approved'")) {
      const row = this.payments.get(values[2]);
      if (!row || row.status !== "pending") return { rows: [], rowCount: 0 };
      Object.assign(row, { status: "approved", decided_by: values[0], decided_at: values[1], updated_at: values[1] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("update payments set status='rejected'")) {
      const row = this.payments.get(values[3]);
      if (!row || row.status !== "pending") return { rows: [], rowCount: 0 };
      Object.assign(row, { status: "rejected", decided_by: values[0], decided_at: values[1], decision_reason: values[2], updated_at: values[1] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("update payments set applied_at=")) {
      const row = this.payments.get(values[1]);
      if (!row) return { rows: [], rowCount: 0 };
      Object.assign(row, { applied_at: values[0], updated_at: values[0] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("insert into payment_events")) {
      this.paymentEvents.push({ payment_id: values[0], event: values[1], detail: values[4] });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("insert into gateway_events")) {
      const key = `${values[0]}:${values[1]}`;
      if (this.gatewayEvents.has(key)) return { rows: [], rowCount: 0 };
      this.gatewayEvents.set(key, {
        provider: values[0], event_id: values[1], event_type: values[2],
        provider_transaction_id: values[3], result: "received", received_at: values[5]
      });
      return { rows: [{ event_id: values[1] }], rowCount: 1 };
    }
    if (sql.startsWith("update gateway_events set result='recorded'")) {
      const row = this.gatewayEvents.get(`${values[0]}:${values[1]}`);
      if (row) row.result = "recorded";
      return { rows: [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("update gateway_events set payment_id=")) {
      const row = this.gatewayEvents.get(`${values[2]}:${values[3]}`);
      if (row) Object.assign(row, { payment_id: values[0], result: values[1] });
      return { rows: [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("insert into admin_sessions")) {
      this.adminSessions.set(values[0], {
        admin_id: values[1],
        csrf_token: values[2],
        expires_at: values[3]
      });
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith("select admin_id, csrf_token, expires_at from admin_sessions")) {
      const row = this.adminSessions.get(values[0]);
      return { rows: row ? [{ ...row }] : [], rowCount: row ? 1 : 0 };
    }
    if (sql.startsWith("delete from admin_sessions where session_hash")) {
      return { rows: [], rowCount: this.adminSessions.delete(values[0]) ? 1 : 0 };
    }
    if (sql.startsWith("delete from admin_sessions where expires_at")) {
      return { rows: [], rowCount: 0 };
    }
    if (sql.startsWith("insert into request_rate_limits")) {
      const [key, windowMs] = values;
      const current = this.rateLimits.get(key);
      const timestamp = Date.now();
      const expired = !current || current.windowStartedAt <= timestamp - windowMs;
      const entry = expired
        ? { windowStartedAt: timestamp, requestCount: 1 }
        : { ...current, requestCount: current.requestCount + 1 };
      this.rateLimits.set(key, entry);
      return { rows: [{ request_count: entry.requestCount }], rowCount: 1 };
    }
    if (sql.startsWith("delete from request_rate_limits where key_hash")) {
      return { rows: [], rowCount: this.rateLimits.delete(values[0]) ? 1 : 0 };
    }
    throw new Error(`Unexpected fake database query: ${sql}`);
  }

  async healthCheck() {
    return { connected: true, serverTime: new Date(now).toISOString() };
  }
}

function createService() {
  const keys = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const database = new FakeDatabase();
  const service = new PostgresLicenseService({
    database,
    plans,
    privateKey: keys.privateKey,
    offlineGraceDays: 2,
    now: () => now
  });
  return { service, database, keys };
}

function validEnvironment(overrides = {}) {
  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  return {
    NODE_ENV: "production",
    SHOPPOS_DATABASE_URL: "postgresql://test:test@localhost:5432/shoppos",
    LICENSE_SIGNING_PRIVATE_KEY: privateKey,
    LICENSE_ADMIN_USERS_JSON: JSON.stringify([{
      id: "test-admin",
      token: crypto.randomBytes(32).toString("base64url"),
      roles: ["licenses:read", "licenses:manage", "licenses:issue"]
    }]),
    LICENSE_PLANS_JSON: JSON.stringify(plans),
    ...overrides
  };
}

test("PostgreSQL configuration validates required server-only values without connecting", () => {
  const configuration = validatePostgresConfiguration(validEnvironment());
  assert.equal(configuration.host, "0.0.0.0");
  assert.equal(configuration.port, 8787);
  assert.equal(configuration.offlineGraceDays, 7);
  assert.equal(configuration.trustedPublicKeys.length, 1);
  assert.throws(() => validatePostgresConfiguration(validEnvironment({ SHOPPOS_DATABASE_URL: "" })), /SHOPPOS_DATABASE_URL/);
  assert.throws(() => validatePostgresConfiguration(validEnvironment({ SHOPPOS_DATABASE_URL: "https://example.invalid" })), /PostgreSQL protocol/);
  assert.throws(() => validatePostgresConfiguration(validEnvironment({
    LICENSE_PLANS_JSON: JSON.stringify([{ ...plans[0], graceDays: 6 }])
  })), /exactly 7 days/);

  let signingKeyError;
  try {
    validatePostgresConfiguration(validEnvironment({
      LICENSE_SIGNING_PRIVATE_KEY: "not-a-valid-private-key"
    }));
  } catch (error) {
    signingKeyError = error;
  }
  assert.equal(signingKeyError?.startupStage, "signing_key_validation");
  assert.equal(signingKeyError?.cause?.code, "ERR_OSSL_UNSUPPORTED");
  assert.equal(getPostgresErrorDiagnostic(signingKeyError).category, "UNKNOWN");
});

test("PostgreSQL configuration trusts explicit old keys and the active signing key", () => {
  const active = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const old = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const configuration = validatePostgresConfiguration(validEnvironment({
    LICENSE_SIGNING_PRIVATE_KEY: active.privateKey,
    LICENSE_TRUSTED_PUBLIC_KEYS_JSON: JSON.stringify([old.publicKey])
  }));
  assert.equal(configuration.trustedPublicKeys.length, 2);
  assert.throws(() => validatePostgresConfiguration(validEnvironment({
    LICENSE_TRUSTED_PUBLIC_KEYS_JSON: JSON.stringify(["not a public key"])
  })), /valid Ed25519 public keys/);
  assert.throws(() => validatePostgresConfiguration(validEnvironment({
    LICENSE_TRUSTED_PUBLIC_KEYS_JSON: JSON.stringify([old.privateKey])
  })), /valid Ed25519 public keys/);
  assert.throws(() => validatePostgresConfiguration(validEnvironment({
    LICENSE_TRUSTED_PUBLIC_KEYS_JSON: JSON.stringify([crypto.createPublicKey(active.privateKey)
      .export({ type: "spki", format: "pem" }).replace("PUBLIC KEY", "RSA PUBLIC KEY")])
  })), /valid Ed25519 public keys|must be Ed25519/);
});

test("PostgreSQL error classification exposes only safe fixed categories", () => {
  const cases = [
    [Object.assign(new Error("connect ECONNREFUSED hidden-host"), { code: "ECONNREFUSED" }), "ECONNREFUSED"],
    [Object.assign(new Error("getaddrinfo ENOTFOUND hidden-host"), { code: "ENOTFOUND" }), "ENOTFOUND"],
    [Object.assign(new Error("connect ETIMEDOUT hidden-host"), { code: "ETIMEDOUT" }), "ETIMEDOUT"],
    [Object.assign(new Error("certificate validation failed"), { code: "ERR_TLS_CERT_ALTNAME_INVALID" }), "TLS_CERTIFICATE_ERROR"],
    [Object.assign(new Error("TLS handshake failed"), { code: "ERR_SSL_WRONG_VERSION_NUMBER" }), "TLS_HANDSHAKE_ERROR"],
    [Object.assign(new Error("OpenSSL private key decoder failure"), { code: "ERR_OSSL_UNSUPPORTED" }), "UNKNOWN"],
    [Object.assign(new Error("password authentication failed for hidden-user"), { code: "28P01" }), "AUTH_ERROR"],
    [Object.assign(new Error("connection failed"), {
      code: "ECONNRESET",
      cause: Object.assign(new Error("TLS negotiation failed"), { code: "ERR_SSL_WRONG_VERSION_NUMBER" })
    }), "TLS_HANDSHAKE_ERROR"],
    [Object.assign(new AggregateError([
      Object.assign(new Error("certificate details contain secrets"), { code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" })
    ], "aggregate failure"), { code: "ECONNRESET" }), "TLS_CERTIFICATE_ERROR"],
    [Object.assign(new Error("connection reset"), { code: "ECONNRESET" }), "CONNECTION_ERROR"],
    [Object.assign(new Error("private diagnostic with token"), { code: "SOME_PRIVATE_CODE" }), "UNKNOWN"]
  ];

  for (const [error, category] of cases) {
    assert.equal(classifyPostgresError(error), category);
  }

  const certificateCodes = [
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "SELF_SIGNED_CERT_IN_CHAIN",
    "CERT_HAS_EXPIRED",
    "ERR_TLS_CERT_ALTNAME_INVALID",
    "UNABLE_TO_GET_ISSUER_CERT"
  ];
  for (const code of certificateCodes) {
    const error = Object.assign(new Error("hidden certificate details"), { code });
    assert.deepEqual(getPostgresErrorDiagnostic(error), {
      category: "TLS_CERTIFICATE_ERROR",
      certificateCode: code
    });
  }

  const nestedError = Object.assign(new Error("wrapper contains private data"), {
    cause: Object.assign(new Error("certificate details contain private data"), {
      code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
    })
  });
  assert.deepEqual(getPostgresErrorDiagnostic(nestedError), {
    category: "TLS_CERTIFICATE_ERROR",
    certificateCode: "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
  });
  assert.deepEqual(getPostgresErrorDiagnostic(Object.assign(new Error("sensitive"), {
    code: "PRIVATE_DATABASE_ERROR"
  })), {
    category: "UNKNOWN",
    certificateCode: null
  });
});

test("pg 8 connection-string sslmode overrides the explicit SSL object without disabling verification", () => {
  const client = new Client({
    connectionString: "postgresql://test:test@localhost:5432/postgres?sslmode=require",
    ssl: { rejectUnauthorized: true }
  });

  assert.deepEqual(client.connectionParameters.ssl, {});
  assert.notEqual(client.connectionParameters.ssl, false);
  assert.equal(client.connectionParameters.ssl.rejectUnauthorized, undefined);
});

test("database CA decoding accepts valid Base64 PEM and rejects missing or invalid values", () => {
  const certificate = tls.rootCertificates[0];
  const encoded = Buffer.from(certificate, "utf8").toString("base64");
  assert.equal(decodeCaCertificate(encoded), certificate);
  assert.equal(decodeCaCertificate(encoded.replace(/.{64}/g, "$&\n")), certificate);
  assert.throws(() => decodeCaCertificate("%%%"), /valid Base64-encoded PEM/);
  assert.throws(() => decodeCaCertificate(Buffer.from("not a certificate").toString("base64")), /valid PEM certificates/);
});

test("pool configuration requires production CA and keeps certificate verification enabled", () => {
  const certificate = tls.rootCertificates[0];
  const encoded = Buffer.from(certificate, "utf8").toString("base64");
  const connectionString = "postgresql://safe-user:safe-pass@db.example:5432/postgres?sslmode=require&application_name=shoppos&options=-c%20search_path%3Dpublic&sslrootcert=%2Fignored.crt";

  assert.throws(() => createPoolConfig(connectionString, {
    caCertificateBase64: undefined,
    production: true
  }), /SHOPPOS_DATABASE_CA_CERT_BASE64 is required in production/);

  const poolConfig = createPoolConfig(connectionString, {
    caCertificateBase64: encoded,
    production: true
  });
  const url = new URL(poolConfig.connectionString);
  assert.equal(url.searchParams.has("sslmode"), false);
  assert.equal(url.searchParams.has("sslrootcert"), false);
  assert.equal(url.searchParams.get("application_name"), "shoppos");
  assert.equal(url.searchParams.get("options"), "-c search_path=public");
  assert.equal(url.username, "safe-user");
  assert.equal(url.password, "safe-pass");

  const client = new Client(poolConfig);
  assert.equal(client.connectionParameters.ssl.rejectUnauthorized, true);
  assert.equal(client.connectionParameters.ssl.ca, certificate);

  const localConfig = createPoolConfig(connectionString, {
    caCertificateBase64: undefined,
    production: false
  });
  const localClient = new Client(localConfig);
  assert.equal(localClient.connectionParameters.ssl.rejectUnauthorized, true);
  assert.equal(localClient.connectionParameters.ssl.ca, undefined);

  assert.throws(() => createPoolConfig(connectionString, {
    caCertificateBase64: "invalid",
    production: true
  }), /valid Base64-encoded PEM/);
});

test("initialization keeps existing plans and only adds serverless support tables", async () => {
  const { service, database } = createService();
  database.planRows[0].name = "Existing Database Plan";
  await service.initialize();
  assert.equal(service.plans.get("monthly").name, "Existing Database Plan");
  assert.equal(database.planInsertCount, 0);

  const mismatched = createService();
  mismatched.database.planRows[0].grace_days = 6;
  mismatched.service.requireFixedGrace = true;
  await assert.rejects(mismatched.service.initialize(), /Every stored production plan must have a 7-day/);
});

test("service initialization failure retains a safe schema stage", async () => {
  const { database, keys } = createService();
  const query = database.query.bind(database);
  database.query = async (statement, values) => {
    if (statement.replace(/\s+/g, " ").trim().toLowerCase().startsWith("select table_name from information_schema.tables")) {
      return { rows: [] };
    }
    return query(statement, values);
  };

  await assert.rejects(
    PostgresLicenseService.create({
      database,
      closeOnInitializationFailure: false,
      plans,
      privateKey: keys.privateKey
    }),
    error => {
      assert.equal(error.startupStage, "schema_table_validation");
      assert.match(error.message, /license schema is incomplete/);
      return true;
    }
  );
});

test("shop creation, activation, signed status checks, and deactivation preserve the desktop token contract", async () => {
  const { service, database } = createService();
  const created = await service.createShop({ shopName: "Corner Shop", planId: "monthly" }, { actorId: "admin" });
  const activated = await service.activate({ licenseKey: created.licenseKey, localShopId: shopId, deviceId });
  assert.equal(activated.status.shopId, created.shopId);
  assert.equal(activated.status.localShopId, shopId);
  const claims = service.verify(activated.token);
  assert.equal(claims.version, 1);
  assert.equal(claims.offlineGraceDays, 2);
  assert.equal(crypto.verify(
    null,
    Buffer.from(activated.token.split(".")[0]),
    service.publicKey,
    Buffer.from(activated.token.split(".")[1], "base64url")
  ), true);
  assert.equal(verifySignedToken(activated.token, crypto.createPublicKey(service.privateKey).export({
    type: "spki",
    format: "pem"
  })).status, "active");
  const status = await service.status({ token: activated.token, localShopId: shopId, deviceId });
  assert.equal(status.status.status, "active");
  assert.equal((await service.deactivate({ token: status.token, localShopId: shopId, deviceId })).deactivated, true);
  await assert.rejects(
    service.status({ token: status.token, localShopId: shopId, deviceId }),
    /no longer activated/
  );
  assert.equal(database.logs.some(log => log.event === "activation_succeeded"), true);
});

test("PostgreSQL verifies old tokens during rotation and signs refreshes only with the active key", async () => {
  const { service, database, keys: oldKeys } = createService();
  const shop = await service.createShop({ shopName: "Rotating Shop", planId: "monthly" });
  const activated = await service.activate({ licenseKey: shop.licenseKey, localShopId: shopId, deviceId });
  assert.equal(verifySignedToken(activated.token, oldKeys.publicKey).status, "active");

  const newKeys = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const rotated = new PostgresLicenseService({
    database,
    plans,
    privateKey: newKeys.privateKey,
    trustedPublicKeys: [crypto.createPublicKey(oldKeys.publicKey)],
    offlineGraceDays: 2,
    now: () => now
  });
  const refreshed = await rotated.status({ token: activated.token, localShopId: shopId, deviceId });
  assert.equal(verifySignedToken(refreshed.token, [oldKeys.publicKey, newKeys.publicKey]).status, "active");
  assert.throws(() => verifySignedToken(refreshed.token, oldKeys.publicKey), /signature/i);
  const [encoded, signature] = activated.token.split(".");
  const invalidSignature = `${encoded}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  assert.throws(() => rotated.verify(invalidSignature), /signature/i);
  assert.equal((await rotated.deactivate({
    token: activated.token,
    localShopId: shopId,
    deviceId
  })).deactivated, true);
});

test("existing-shop registration and license issuance bind the license to its local shop", async () => {
  const { service } = createService();
  const shop = await service.registerExistingShop({
    localShopId: shopId,
    confirmationShopId: shopId,
    shopName: "Existing Shop"
  }, { actorId: "admin" });
  const issued = await service.createLicenseForShop(shop.id, {
    confirmedLocalShopId: shopId,
    planId: "monthly"
  }, { actorId: "admin" });
  assert.equal(issued.intendedLocalShopId, shopId);
  assert.match(issued.licenseKey, /^SP-/);
  await assert.rejects(service.activate({
    licenseKey: issued.licenseKey,
    localShopId: "13814000-1dd2-11b2-8000-000000000002",
    deviceId
  }), /different ShopPOS shop/);
});

test("renewal, payment approval and rejection are transactional and use row locks", async () => {
  const { service, database } = createService();
  const created = await service.createShop({ shopName: "Payments Shop", planId: "monthly" });
  const activated = await service.activate({ licenseKey: created.licenseKey, localShopId: shopId, deviceId });
  const submitted = await service.submitManualPayment({
    token: activated.token,
    localShopId: shopId,
    deviceId,
    planId: "monthly",
    amountMinor: 4200,
    currency: "USD",
    reference: "PAY-1001"
  });
  assert.equal(submitted.status, "pending");
  const approved = await service.approvePayment(submitted.id, { actorId: "admin" });
  assert.equal(approved.payment.status, "approved");
  assert.ok(approved.payment.appliedAt);
  assert.equal(database.licenses.get(created.licenseId).expires_at, approved.license.expiresAt);
  await assert.rejects(service.approvePayment(submitted.id, { actorId: "admin" }), /already decided/);

  const rejectedSubmission = await service.submitManualPayment({
    token: activated.token,
    localShopId: shopId,
    deviceId,
    planId: "monthly",
    amountMinor: 4200,
    currency: "USD",
    reference: "PAY-1002"
  });
  const rejected = await service.rejectPayment(rejectedSubmission.id, {
    actorId: "admin",
    reason: "Payment could not be verified"
  });
  assert.equal(rejected.status, "rejected");
  assert.ok(database.lockedQueries.some(sql => sql.startsWith("select * from payments")));
});

test("gateway event processing is idempotent and license state changes are locked", async () => {
  const { service, database } = createService();
  const created = await service.createShop({ shopName: "State Shop", planId: "monthly" });
  const first = await service.recordGatewayEvent("test", {
    eventId: "event-1",
    eventType: "payment.updated",
    transactionId: "transaction-1",
    status: "unknown"
  });
  const duplicate = await service.recordGatewayEvent("test", {
    eventId: "event-1",
    eventType: "payment.updated",
    transactionId: "transaction-1",
    status: "unknown"
  });
  assert.deepEqual(first, { duplicate: false, applied: false });
  assert.deepEqual(duplicate, { duplicate: true, applied: false });
  const suspended = await service.changeState(created.licenseId, "suspended", { actorId: "admin" });
  assert.equal(suspended.status, "suspended");
  const reactivated = await service.changeState(created.licenseId, "reactivated", { actorId: "admin" });
  assert.equal(reactivated.status, "active");
  assert.ok(database.lockedQueries.length > 0);
});

test("admin sessions and rate limits persist through parameterized database operations", async () => {
  const { service, database } = createService();
  await service.createAdminSession("opaque-session-id", {
    adminId: "test-admin",
    csrfToken: "test-csrf-token",
    expiresAt: now + 60_000
  });
  assert.deepEqual(await service.getAdminSession("opaque-session-id"), {
    adminId: "test-admin",
    csrfToken: "test-csrf-token",
    expiresAt: now + 60_000
  });
  assert.equal(await service.consumeRateLimit("admin-login", "test-ip", 2, 60_000), true);
  assert.equal(await service.consumeRateLimit("admin-login", "test-ip", 2, 60_000), true);
  assert.equal(await service.consumeRateLimit("admin-login", "test-ip", 2, 60_000), false);
  await service.resetRateLimit("admin-login", "test-ip");
  assert.equal(database.rateLimits.size, 0);
  await service.deleteAdminSession("opaque-session-id");
  assert.equal(await service.getAdminSession("opaque-session-id"), undefined);
});

test("admin cookie sessions survive an HTTP handler restart and retain CSRF protection", async t => {
  const { service } = createService();
  const adminToken = crypto.randomBytes(32).toString("base64url");
  const admins = [{
    id: "test-admin",
    token: adminToken,
    roles: ["licenses:read", "licenses:manage", "licenses:issue"]
  }];
  let server = createLicenseServer({ service, admins, port: 0 });
  let address = await server.listen();
  let baseUrl = `http://127.0.0.1:${address.port}`;
  t.after(async () => server.close().catch(() => undefined));

  const login = await fetch(`${baseUrl}/admin/session`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${adminToken}`,
      origin: baseUrl,
      "content-type": "application/json"
    },
    body: "{}"
  });
  assert.equal(login.status, 200);
  const loginBody = await login.json();
  const cookie = login.headers.get("set-cookie").split(";")[0];
  await server.close();

  server = createLicenseServer({ service, admins, port: 0 });
  address = await server.listen();
  baseUrl = `http://127.0.0.1:${address.port}`;
  const session = await fetch(`${baseUrl}/admin/session`, { headers: { cookie } });
  assert.equal(session.status, 200);
  assert.equal((await session.json()).administrator.id, "test-admin");

  const deniedWrite = await fetch(`${baseUrl}/admin/shops`, {
    method: "POST",
    headers: {
      cookie,
      origin: baseUrl,
      "content-type": "application/json"
    },
    body: JSON.stringify({ shopName: "Not created", planId: "monthly" })
  });
  assert.equal(deniedWrite.status, 403);
  assert.match((await deniedWrite.json()).error, /CSRF token/);
  assert.ok(loginBody.csrfToken);
});

test("Vercel health endpoint reports only generic service and database status", async () => {
  const serverModule = require("./server.cjs");
  const databaseModule = require("./database.cjs");
  const routePath = require.resolve("../api/[...route].js");
  const originalCreatePostgresService = serverModule.createPostgresService;
  const originalValidateConfiguration = serverModule.validatePostgresConfiguration;
  const originalCreateDatabase = databaseModule.createDatabase;
  const originalConsoleError = console.error;
  const loggedErrors = [];
  let databaseFailure = null;
  let serviceAvailable = false;
  let serviceHealthFailure = null;

  serverModule.validatePostgresConfiguration = () => ({
    admins: [{
      id: "health-test",
      token: crypto.randomBytes(32).toString("base64url"),
      roles: ["licenses:read"]
    }]
  });
  serverModule.createPostgresService = async () => {
    if (serviceAvailable) {
      return {
        db: {
          async healthCheck() {
            if (serviceHealthFailure) throw serviceHealthFailure;
            return { connected: true };
          }
        }
      };
    }
    throw Object.assign(new Error("postgresql://admin:secret@db.example/shoppos password=private"), {
      startupStage: "schema_table_validation"
    });
  };
  databaseModule.createDatabase = () => ({
    async healthCheck() {
      if (databaseFailure) throw databaseFailure;
      return { connected: true };
    },
    async close() {}
  });
  console.error = (...args) => loggedErrors.push(args);
  delete require.cache[routePath];

  try {
    const handler = require(routePath);
    async function requestHealth() {
      const response = {
        headersSent: false,
        writeHead(status, headers) {
          this.status = status;
          this.headers = headers;
          this.headersSent = true;
        },
        end(body) {
          this.body = body;
        }
      };
      await handler({
        method: "GET",
        url: "/api/health",
        headers: { host: "localhost" }
      }, response);
      return response;
    }

    const connected = await requestHealth();
    assert.equal(connected.status, 503);
    assert.deepEqual(JSON.parse(connected.body), {
      service: "unavailable",
      database: "connected",
      databaseError: null,
      databaseCertificateError: null,
      serviceError: "UNKNOWN",
      serviceFailureStage: "schema_table_validation",
      serviceCertificateError: null
    });
    assert.equal(connected.headers["cache-control"], "no-store");
    assert.doesNotMatch(connected.body, /secret|private|admin|postgresql/i);

    databaseFailure = Object.assign(
      new Error("Connection failed for hidden-user at hidden-host password hidden-password"),
      { code: "ENOTFOUND" }
    );
    const unavailable = await requestHealth();
    assert.equal(unavailable.status, 503);
    assert.deepEqual(JSON.parse(unavailable.body), {
      service: "unavailable",
      database: "unavailable",
      databaseError: "ENOTFOUND",
      databaseCertificateError: null,
      serviceError: "UNKNOWN",
      serviceFailureStage: "schema_table_validation",
      serviceCertificateError: null
    });
    assert.doesNotMatch(unavailable.body, /hidden-user|hidden-host|hidden-password|postgresql/i);
    assert.doesNotMatch(JSON.stringify(loggedErrors), /hidden-user|hidden-host|hidden-password/);
    assert.ok(loggedErrors.some(([, details]) => details.category === "ENOTFOUND"));

    databaseFailure = Object.assign(
      new Error("certificate details contain hidden-host and hidden-user"),
      { code: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }
    );
    const certificateFailure = await requestHealth();
    assert.deepEqual(JSON.parse(certificateFailure.body), {
      service: "unavailable",
      database: "unavailable",
      databaseError: "TLS_CERTIFICATE_ERROR",
      databaseCertificateError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
      serviceError: "UNKNOWN",
      serviceFailureStage: "schema_table_validation",
      serviceCertificateError: null
    });
    assert.doesNotMatch(certificateFailure.body, /hidden-host|hidden-user|certificate details/i);
    assert.ok(loggedErrors.some(([, details]) =>
      details.category === "TLS_CERTIFICATE_ERROR" &&
      details.certificateCode === "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
    ));

    databaseFailure = Object.assign(
      new Error("protocol details contain hidden-host and hidden-user"),
      { code: "ERR_SSL_WRONG_VERSION_NUMBER" }
    );
    const handshakeFailure = await requestHealth();
    assert.deepEqual(JSON.parse(handshakeFailure.body), {
      service: "unavailable",
      database: "unavailable",
      databaseError: "TLS_HANDSHAKE_ERROR",
      databaseCertificateError: null,
      serviceError: "UNKNOWN",
      serviceFailureStage: "schema_table_validation",
      serviceCertificateError: null
    });
    assert.doesNotMatch(handshakeFailure.body, /hidden-host|hidden-user|protocol details/i);

    serviceAvailable = true;
    databaseFailure = null;
    const ready = await requestHealth();
    assert.equal(ready.status, 200);
    assert.deepEqual(JSON.parse(ready.body), {
      service: "available",
      database: "connected",
      databaseError: null,
      databaseCertificateError: null,
      serviceError: null,
      serviceFailureStage: null,
      serviceCertificateError: null
    });

    serviceHealthFailure = new Error("service health probe failed");
    const healthFailure = await requestHealth();
    assert.equal(healthFailure.status, 503);
    assert.deepEqual(JSON.parse(healthFailure.body), {
      service: "unavailable",
      database: "connected",
      databaseError: null,
      databaseCertificateError: null,
      serviceError: "UNKNOWN",
      serviceFailureStage: "service_health_check",
      serviceCertificateError: null
    });

    serverModule.validatePostgresConfiguration = () => {
      throw Object.assign(
        new Error("LICENSE_SIGNING_PRIVATE_KEY validation failed"),
        {
          startupStage: "signing_key_validation",
          cause: Object.assign(new Error("private diagnostic detail"), {
            code: "ERR_OSSL_UNSUPPORTED"
          })
        }
      );
    };
    delete require.cache[routePath];
    const configurationFailureHandler = require(routePath);
    const configurationFailure = await (async () => {
      const response = {
        headersSent: false,
        writeHead(status, headers) {
          this.status = status;
          this.headers = headers;
          this.headersSent = true;
        },
        end(body) {
          this.body = body;
        }
      };
      await configurationFailureHandler({
        method: "GET",
        url: "/api/health",
        headers: { host: "localhost" }
      }, response);
      return response;
    })();
    assert.equal(configurationFailure.status, 503);
    assert.deepEqual(JSON.parse(configurationFailure.body), {
      service: "unavailable",
      database: "connected",
      databaseError: null,
      databaseCertificateError: null,
      serviceError: "CONFIGURATION_ERROR",
      serviceFailureStage: "signing_key_validation",
      serviceCertificateError: null
    });
    assert.doesNotMatch(configurationFailure.body, /private diagnostic detail|ERR_OSSL|LICENSE_SIGNING_PRIVATE_KEY/);
  } finally {
    delete require.cache[routePath];
    serverModule.createPostgresService = originalCreatePostgresService;
    serverModule.validatePostgresConfiguration = originalValidateConfiguration;
    databaseModule.createDatabase = originalCreateDatabase;
    console.error = originalConsoleError;
  }
});

test("health signing-key diagnostic accepts optional admins only on the diagnostic query", async () => {
  const routePath = require.resolve("../api/[...route].js");
  const serverModule = require("./server.cjs");
  const originalCreatePostgresService = serverModule.createPostgresService;
  const originalValidateConfiguration = serverModule.validatePostgresConfiguration;
  const { privateKey: ed25519PrivateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const { privateKey: rsaPrivateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const adminToken = crypto.randomBytes(32).toString("base64url");
  const readOnlyToken = crypto.randomBytes(32).toString("base64url");
  const diagnosticToken = crypto.randomBytes(32).toString("base64url");
  const previousPrivateKey = process.env.LICENSE_SIGNING_PRIVATE_KEY;
  const hadPrivateKey = Object.hasOwn(process.env, "LICENSE_SIGNING_PRIVATE_KEY");
  const previousAdmins = process.env.LICENSE_ADMIN_USERS_JSON;
  const hadAdmins = Object.hasOwn(process.env, "LICENSE_ADMIN_USERS_JSON");
  const previousDiagnosticAdmins = process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON;
  const hadDiagnosticAdmins = Object.hasOwn(process.env, "LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON");
  process.env.LICENSE_ADMIN_USERS_JSON = JSON.stringify([
    { id: "diagnostic-admin", token: adminToken, roles: ["licenses:read", "licenses:manage"] },
    { id: "diagnostic-reader", token: readOnlyToken, roles: ["licenses:read"] }
  ]);
  process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON = JSON.stringify([
    { id: "temporary-diagnostic-admin", token: diagnosticToken, roles: ["licenses:manage"] }
  ]);
  serverModule.validatePostgresConfiguration = () => ({
    admins: JSON.parse(process.env.LICENSE_ADMIN_USERS_JSON)
  });
  serverModule.createPostgresService = async () => ({
    async listShops() {
      return [];
    }
  });
  delete require.cache[routePath];

  try {
    const handler = require(routePath);
    async function request({
      token,
      url = "/api/health?diagnostic=signing-key",
      signingKey = ed25519PrivateKey,
      unsetSigningKey = false
    } = {}) {
      if (unsetSigningKey) delete process.env.LICENSE_SIGNING_PRIVATE_KEY;
      else process.env.LICENSE_SIGNING_PRIVATE_KEY = signingKey;
      const response = {
        headersSent: false,
        writeHead(status, headers) {
          this.status = status;
          this.headers = headers;
          this.headersSent = true;
        },
        end(body) {
          this.body = body;
        }
      };
      await handler({
        method: "GET",
        url,
        headers: token ? { authorization: `Bearer ${token}` } : {},
        socket: { remoteAddress: "127.0.0.1" },
        async *[Symbol.asyncIterator]() {}
      }, response);
      return response;
    }

    const unauthenticated = await request({});
    assert.equal(unauthenticated.status, 401);

    const readOnly = await request({ token: readOnlyToken });
    assert.equal(readOnly.status, 403);

    for (const token of [adminToken, diagnosticToken]) {
      const authorized = await request({ token });
      assert.equal(authorized.status, 200);
      assert.deepEqual(JSON.parse(authorized.body), {
        containsActualNewline: true,
        containsEscapedNewline: false,
        pemMarkersPresent: true,
        parseSucceeded: true,
        isEd25519: true
      });
      assert.equal(authorized.headers["cache-control"], "no-store");
    }

    const diagnosticOnlyOnQuery = await request({
      token: diagnosticToken,
      url: "/api/admin/temporary/signing-key-diagnostic"
    });
    assert.equal(diagnosticOnlyOnQuery.status, 401);

    const normalAdminRoute = await request({
      token: diagnosticToken,
      url: "/api/admin/shops"
    });
    assert.equal(normalAdminRoute.status, 401);

    const existingAdminRoute = await request({
      token: adminToken,
      url: "/api/admin/shops"
    });
    assert.equal(existingAdminRoute.status, 200);
    assert.deepEqual(JSON.parse(existingAdminRoute.body), { shops: [] });

    delete process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON;
    assert.equal((await request({ token: adminToken })).status, 200);
    process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON = "";
    assert.equal((await request({ token: adminToken })).status, 200);

    const invalidConfigurations = [
      "{",
      JSON.stringify([{ id: "diagnostic-admin", token: crypto.randomBytes(32).toString("base64url"), roles: ["licenses:manage"] }]),
      JSON.stringify([{ id: "another-diagnostic-admin", token: adminToken, roles: ["licenses:manage"] }]),
      JSON.stringify([{ id: "invalid-role", token: crypto.randomBytes(32).toString("base64url"), roles: ["administrator"] }]),
      JSON.stringify([{ id: "short-token", token: "too-short", roles: ["licenses:manage"] }])
    ];
    for (const invalidConfiguration of invalidConfigurations) {
      process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON = invalidConfiguration;
      const unavailable = await request({ token: adminToken });
      assert.equal(unavailable.status, 503);
      assert.deepEqual(JSON.parse(unavailable.body), {
        error: "The temporary diagnostic is unavailable."
      });
      assert.doesNotMatch(unavailable.body, /token|secret|credential/i);
    }
    const regularAdminUnaffected = await request({
      token: adminToken,
      url: "/api/admin/shops"
    });
    assert.equal(regularAdminUnaffected.status, 200);

    process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON = JSON.stringify([
      { id: "temporary-diagnostic-admin", token: diagnosticToken, roles: ["licenses:manage"] }
    ]);
    const missingKey = await request({ token: adminToken, unsetSigningKey: true });
    assert.deepEqual(JSON.parse(missingKey.body), {
      containsActualNewline: false,
      containsEscapedNewline: false,
      pemMarkersPresent: false,
      parseSucceeded: false,
      isEd25519: false
    });

    const malformed = await request({ token: adminToken, signingKey: "not-a-key" });
    assert.equal(malformed.status, 200);
    assert.deepEqual(JSON.parse(malformed.body), {
      containsActualNewline: false,
      containsEscapedNewline: false,
      pemMarkersPresent: false,
      parseSucceeded: false,
      isEd25519: false
    });

    const escapedNewlines = ed25519PrivateKey.replace(/\n/g, "\\n");
    const validEscaped = await request({ token: diagnosticToken, signingKey: escapedNewlines });
    assert.deepEqual(JSON.parse(validEscaped.body), {
      containsActualNewline: false,
      containsEscapedNewline: true,
      pemMarkersPresent: true,
      parseSucceeded: true,
      isEd25519: true
    });

    const wrongType = await request({ token: diagnosticToken, signingKey: rsaPrivateKey });
    assert.deepEqual(JSON.parse(wrongType.body), {
      containsActualNewline: true,
      containsEscapedNewline: false,
      pemMarkersPresent: true,
      parseSucceeded: true,
      isEd25519: false
    });
    assert.doesNotMatch(
      JSON.stringify([unauthenticated.body, readOnly.body, missingKey.body, malformed.body, wrongType.body]),
      /BEGIN|PRIVATE KEY|public key|fingerprint|exception|stack|token|credential/i
    );
  } finally {
    delete require.cache[routePath];
    serverModule.createPostgresService = originalCreatePostgresService;
    serverModule.validatePostgresConfiguration = originalValidateConfiguration;
    if (hadPrivateKey) process.env.LICENSE_SIGNING_PRIVATE_KEY = previousPrivateKey;
    else delete process.env.LICENSE_SIGNING_PRIVATE_KEY;
    if (hadAdmins) process.env.LICENSE_ADMIN_USERS_JSON = previousAdmins;
    else delete process.env.LICENSE_ADMIN_USERS_JSON;
    if (hadDiagnosticAdmins) process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON = previousDiagnosticAdmins;
    else delete process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON;
  }
});
