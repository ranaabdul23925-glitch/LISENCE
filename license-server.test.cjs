const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { verifySignedToken } = require("../desktop/license.cjs");
const { createLicenseServer, initializeService, validateServerConfiguration } = require("./license-server.cjs");

const ADMIN_TOKEN = crypto.randomBytes(32).toString("base64url");
const admins = [{ id: "test-admin", token: ADMIN_TOKEN, roles: ["licenses:issue", "licenses:read", "licenses:manage"] }];
const plans = [
  { id: "monthly", name: "Monthly", interval: "monthly", priceMinor: 4200, currency: "USD", trialDays: 0, graceDays: 7 },
  { id: "yearly", name: "Yearly", interval: "yearly", priceMinor: 40000, currency: "USD", trialDays: 14, graceDays: 7 }
];

function validServerEnvironment(overrides = {}) {
  const { privateKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  return {
    NODE_ENV: "test",
    LICENSE_SIGNING_PRIVATE_KEY: privateKey,
    LICENSE_PLANS_JSON: JSON.stringify(plans),
    LICENSE_ADMIN_USERS_JSON: JSON.stringify([{
      id: "config-admin",
      token: crypto.randomBytes(32).toString("base64url"),
      roles: ["licenses:issue", "licenses:read", "licenses:manage"]
    }]),
    ...overrides
  };
}

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "shoppos-license-server-"));
  const keys = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  let now = Date.parse("2026-01-15T12:00:00.000Z");
  const serviceOptions = {
    databasePath: path.join(root, "licenses.sqlite"),
    plans,
    privateKey: keys.privateKey,
    offlineGraceDays: 2,
    now: () => now
  };
  let service = await initializeService(serviceOptions);
  let running = createLicenseServer({ service, admins, port: 0 });
  let address = await running.listen();
  let url = `http://127.0.0.1:${address.port}`;
  t.after(async () => {
    await running.close().catch(() => undefined);
    service.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  return {
    keys,
    get service() { return service; },
    get url() { return url; },
    setNow(value) { now = value; },
    async stopServer() { await running.close(); },
    async restartServer() {
      await running.close();
      service.close();
      service = await initializeService(serviceOptions);
      running = createLicenseServer({ service, admins, port: 0 });
      address = await running.listen();
      url = `http://127.0.0.1:${address.port}`;
    },
    async request(route, { method = "POST", body = {}, admin = false, headers: extraHeaders = {} } = {}) {
      const response = await fetch(`${url}${route}`, {
        method,
        headers: {
          ...extraHeaders,
          "content-type": "application/json",
          ...(admin ? { authorization: `Bearer ${ADMIN_TOKEN}` } : {})
        },
        body: method === "GET" ? undefined : JSON.stringify(body)
      });
      return { status: response.status, body: await response.json() };
    },
    async createLicense(planId = "monthly", shopName = "Corner Shop") {
      const response = await this.request("/admin/shops", { body: { shopName, planId }, admin: true });
      assert.equal(response.status, 201);
      return response.body;
    }
  };
}

test("server configuration requires admin users and validates their credentials and roles", () => {
  const missingPrivateKey = validServerEnvironment();
  delete missingPrivateKey.LICENSE_SIGNING_PRIVATE_KEY;
  assert.throws(() => validateServerConfiguration(missingPrivateKey), /LICENSE_SIGNING_PRIVATE_KEY/i);

  const missingPlans = validServerEnvironment();
  delete missingPlans.LICENSE_PLANS_JSON;
  assert.throws(() => validateServerConfiguration(missingPlans), /LICENSE_PLANS_JSON/i);

  const missingAdmins = validServerEnvironment();
  delete missingAdmins.LICENSE_ADMIN_USERS_JSON;
  assert.throws(() => validateServerConfiguration(missingAdmins), /LICENSE_ADMIN_USERS_JSON/i);

  const configuration = validateServerConfiguration(validServerEnvironment());
  assert.equal(configuration.trustedPublicKeys.length, 1);
  assert.equal(configuration.admins.length, 1);
  assert.deepEqual(configuration.admins[0].roles, ["licenses:issue", "licenses:read", "licenses:manage"]);
  assert.equal(configuration.host, "127.0.0.1");
  assert.equal(configuration.port, 8787);
  assert.equal(configuration.offlineGraceDays, 7);
  assert.equal(validateServerConfiguration(validServerEnvironment({ PORT: "10000" })).port, 10000);
  assert.equal(validateServerConfiguration(validServerEnvironment({
    LICENSE_PORT: "8788",
    PORT: "10000"
  })).port, 8788);
  assert.equal(validateServerConfiguration(validServerEnvironment({
    LICENSE_PORT: "",
    PORT: "10000"
  })).port, 10000);
  assert.throws(() => validateServerConfiguration(validServerEnvironment({ PORT: "invalid" })), /LICENSE_PORT or PORT/i);
  assert.equal(
    configuration.databasePath,
    path.join(__dirname, "data", "licenses.sqlite")
  );

  const shortToken = validServerEnvironment({
    LICENSE_ADMIN_USERS_JSON: JSON.stringify([{
      id: "short-token",
      token: "too-short",
      roles: ["licenses:read"]
    }])
  });
  assert.throws(() => validateServerConfiguration(shortToken), /at least 32 bytes/i);

  const unsupportedRole = validServerEnvironment({
    LICENSE_ADMIN_USERS_JSON: JSON.stringify([{
      id: "unsupported-role",
      token: crypto.randomBytes(32).toString("base64url"),
      roles: ["administrator"]
    }])
  });
  assert.throws(() => validateServerConfiguration(unsupportedRole), /supported roles/i);

  const activeKey = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const oldKey = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const multiKeyConfiguration = validateServerConfiguration(validServerEnvironment({
    LICENSE_SIGNING_PRIVATE_KEY: activeKey.privateKey,
    LICENSE_TRUSTED_PUBLIC_KEYS_JSON: JSON.stringify([oldKey.publicKey])
  }));
  assert.equal(multiKeyConfiguration.trustedPublicKeys.length, 2);
  assert.throws(() => validateServerConfiguration(validServerEnvironment({
    LICENSE_TRUSTED_PUBLIC_KEYS_JSON: "{invalid"
  })), /LICENSE_TRUSTED_PUBLIC_KEYS_JSON/);
});

test("production server configuration requires an absolute persistent database path", () => {
  const environment = validServerEnvironment({ NODE_ENV: "production" });
  assert.throws(() => validateServerConfiguration(environment), /LICENSE_DATABASE_PATH/i);

  const relativePath = validServerEnvironment({
    NODE_ENV: "production",
    LICENSE_DATABASE_PATH: path.join("data", "licenses.sqlite")
  });
  assert.throws(() => validateServerConfiguration(relativePath), /absolute/i);

  const placeholderPath = validServerEnvironment({
    NODE_ENV: "production",
    LICENSE_DATABASE_PATH: "replace-with-persistent-file"
  });
  assert.throws(() => validateServerConfiguration(placeholderPath), /placeholder/i);

  const persistentPath = path.join(os.tmpdir(), "shoppos-production-license.sqlite");
  const production = validateServerConfiguration(validServerEnvironment({
    NODE_ENV: "production",
    LICENSE_DATABASE_PATH: persistentPath
  }));
  assert.equal(production.databasePath, path.resolve(persistentPath));
});

test("version 2 license databases migrate without losing shops, licenses, bindings, or history", async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "shoppos-license-migration-"));
  const databasePath = path.join(root, "licenses.sqlite");
  const keyPair = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  const initializeSqlJs = require("sql.js");
  const wasmBinary = fs.readFileSync(require.resolve("sql.js/dist/sql-wasm.wasm"));
  const SQL = await initializeSqlJs({ wasmBinary });
  const database = new SQL.Database();
  const legacyShopId = crypto.randomUUID();
  const legacyLicenseId = crypto.randomUUID();
  const existingLocalShopId = crypto.randomUUID();
  const existingDeviceId = crypto.randomUUID();
  database.run(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE shops (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE licenses (
      id TEXT PRIMARY KEY, shop_id TEXT NOT NULL REFERENCES shops(id), key_hash TEXT NOT NULL UNIQUE,
      plan_id TEXT NOT NULL, state TEXT NOT NULL, starts_at TEXT NOT NULL, expires_at TEXT NOT NULL,
      trial_ends_at TEXT, local_shop_id TEXT, device_id TEXT, activated_at TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE license_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT, license_id TEXT, actor_id TEXT, event TEXT NOT NULL,
      local_shop_id TEXT, device_id TEXT, remote_address TEXT, created_at TEXT NOT NULL, detail TEXT NOT NULL
    );
    PRAGMA user_version = 2;
  `);
  database.run("INSERT INTO shops VALUES (?, ?, ?)", [legacyShopId, "Legacy Shop", "2025-01-01T00:00:00.000Z"]);
  database.run(`
    INSERT INTO licenses VALUES (?, ?, ?, ?, 'active', ?, ?, NULL, ?, ?, ?, ?, ?)
  `, [
    legacyLicenseId, legacyShopId, "legacy-hash", "monthly",
    "2025-01-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z",
    existingLocalShopId, existingDeviceId, "2025-01-02T00:00:00.000Z",
    "2025-01-01T00:00:00.000Z", "2025-01-02T00:00:00.000Z"
  ]);
  database.run("INSERT INTO license_logs (license_id, actor_id, event, created_at, detail) VALUES (?, ?, ?, ?, ?)", [
    legacyLicenseId, "legacy-admin", "license_created", "2025-01-01T00:00:00.000Z", ""
  ]);
  fs.writeFileSync(databasePath, Buffer.from(database.export()));
  database.close();

  let service;
  t.after(() => {
    service?.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  service = await initializeService({ databasePath, plans, privateKey: keyPair.privateKey });
  assert.equal(service.db.exec("PRAGMA user_version")[0].values[0][0], 4);
  assert.equal(service.query("SELECT name FROM shops WHERE id = ?", [legacyShopId]).name, "Legacy Shop");
  const migrated = service.query("SELECT * FROM licenses WHERE id = ?", [legacyLicenseId]);
  assert.equal(migrated.local_shop_id, existingLocalShopId);
  assert.equal(migrated.device_id, existingDeviceId);
  assert.equal(migrated.key_redeemed_at, "2025-01-02T00:00:00.000Z");
  assert.equal(service.logs(legacyLicenseId)[0].actorId, "legacy-admin");
  assert.equal(service.listPlans().length, plans.length);
});

test("authenticated issuance and activation return a valid shop-bound signed entitlement", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  assert.match(license.shopId, /^[0-9a-f-]{36}$/i);
  assert.match(license.licenseId, /^[0-9a-f-]{36}$/i);
  assert.equal(license.priceMinor, 4200);
  assert.equal((await env.request("/admin/shops", { body: { shopName: "Unauthenticated", planId: "monthly" } })).status, 401);

  const localShopId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  const activation = await env.request("/v1/activate", {
    body: { licenseKey: license.licenseKey, localShopId, deviceId }
  });
  assert.equal(activation.status, 200);
  const claims = verifySignedToken(activation.body.token, env.keys.publicKey);
  assert.equal(claims.localShopId, localShopId);
  assert.equal(claims.deviceId, deviceId);
  assert.equal(claims.shopId, license.shopId);
  assert.equal(claims.licenseId, license.licenseId);
  assert.equal(claims.status, "active");

  const status = await env.request("/v1/status", {
    body: { token: activation.body.token, localShopId, deviceId }
  });
  assert.equal(status.status, 200);
  assert.equal(verifySignedToken(status.body.token, env.keys.publicKey).status, "active");
});

test("legacy SQLite server accepts old tokens during rotation and signs only with the active key", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });
  assert.equal(activation.status, 200);
  const oldToken = activation.body.token;
  assert.equal(verifySignedToken(oldToken, env.keys.publicKey).status, "active");

  const newKeys = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" }
  });
  env.service.privateKey = crypto.createPrivateKey(newKeys.privateKey);
  env.service.publicKey = crypto.createPublicKey(env.service.privateKey);
  env.service.trustedPublicKeys = [
    env.service.publicKey,
    crypto.createPublicKey(env.keys.publicKey)
  ];

  const status = await env.request("/v1/status", { body: { ...binding, token: oldToken } });
  assert.equal(status.status, 200);
  assert.equal(verifySignedToken(status.body.token, [env.keys.publicKey, newKeys.publicKey]).status, "active");
  assert.throws(() => verifySignedToken(status.body.token, env.keys.publicKey), /signature/i);
  assert.equal((await env.request("/v1/deactivate", { body: { ...binding, token: oldToken } })).status, 200);
  const [encoded, signature] = oldToken.split(".");
  const invalidSignature = `${encoded}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  assert.throws(() => env.service.verify(invalidSignature), /signature/i);
});

test("invalid license keys and attempts to reuse a license for another shop are rejected", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const invalid = await env.request("/v1/activate", {
    body: { licenseKey: "SP-invalid", localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() }
  });
  assert.equal(invalid.status, 401);

  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  assert.equal((await env.request("/v1/activate", { body: { ...binding, licenseKey: license.licenseKey } })).status, 200);
  const reused = await env.request("/v1/activate", {
    body: { licenseKey: license.licenseKey, localShopId: crypto.randomUUID(), deviceId: binding.deviceId }
  });
  assert.equal(reused.status, 403);
});

test("trial, expiry, suspension, reactivation and revocation produce authoritative statuses", async t => {
  const env = await fixture(t);
  const trial = await env.createLicense("yearly", "Trial Shop");
  assert.equal(trial.status, "trial");
  assert.ok(trial.trialEndsAt);
  const trialActivation = await env.request("/v1/activate", {
    body: { licenseKey: trial.licenseKey, localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() }
  });
  assert.equal(verifySignedToken(trialActivation.body.token, env.keys.publicKey).status, "trial");

  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", { body: { ...binding, licenseKey: license.licenseKey } });
  env.service.db.run("UPDATE licenses SET starts_at = ?, expires_at = ? WHERE id = ?", [
    "2026-01-01T12:00:00.000Z",
    "2026-01-01T12:00:00.000Z",
    license.licenseId
  ]);
  const expired = await env.request("/v1/status", {
    body: { ...binding, token: activation.body.token }
  });
  assert.equal(verifySignedToken(expired.body.token, env.keys.publicKey).status, "expired");

  await env.request(`/admin/licenses/${license.licenseId}/suspend`, { admin: true });
  const suspended = await env.request("/v1/status", { body: { ...binding, token: expired.body.token } });
  assert.equal(verifySignedToken(suspended.body.token, env.keys.publicKey).status, "suspended");
  assert.equal((await env.request(`/admin/licenses/${license.licenseId}/reactivate`, { admin: true })).body.status, "expired");

  await env.request(`/admin/licenses/${license.licenseId}/revoke`, { admin: true });
  const revoked = await env.request("/v1/status", { body: { ...binding, token: suspended.body.token } });
  assert.equal(verifySignedToken(revoked.body.token, env.keys.publicKey).status, "revoked");
});

test("expired and revoked unredeemed activation keys cannot be activated", async t => {
  const env = await fixture(t);
  const expired = await env.createLicense();
  env.service.db.run("UPDATE licenses SET starts_at = ?, expires_at = ? WHERE id = ?", [
    "2025-01-01T00:00:00.000Z", "2025-01-02T00:00:00.000Z", expired.licenseId
  ]);
  const expiredResult = await env.request("/v1/activate", {
    body: { licenseKey: expired.licenseKey, localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() }
  });
  assert.notEqual(expiredResult.status, 200);
  assert.match(expiredResult.body.error, /expired/i);

  const revoked = await env.createLicense();
  await env.request(`/admin/licenses/${revoked.licenseId}/revoke`, { admin: true });
  const revokedResult = await env.request("/v1/activate", {
    body: { licenseKey: revoked.licenseKey, localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() }
  });
  assert.notEqual(revokedResult.status, 200);
  assert.match(revokedResult.body.error, /revoked/i);
});

test("renewal extends the configured plan term without replacing the assigned license", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  env.service.db.run("UPDATE licenses SET expires_at = ? WHERE id = ?", ["2026-01-10T12:00:00.000Z", license.licenseId]);
  const renewed = await env.request(`/admin/licenses/${license.licenseId}/renew`, { admin: true });
  assert.equal(renewed.status, 200);
  assert.equal(renewed.body.licenseId, license.licenseId);
  assert.equal(renewed.body.status, "active");
  assert.equal(renewed.body.expiresAt, "2026-02-15T12:00:00.000Z");
  assert.ok(env.service.logs(license.licenseId).some(log => log.event === "renewal"));
});

test("wrong-shop status checks and tampered signed entitlements are rejected", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", { body: { ...binding, licenseKey: license.licenseKey } });
  const wrongShop = await env.request("/v1/status", {
    body: { ...binding, localShopId: crypto.randomUUID(), token: activation.body.token }
  });
  assert.equal(wrongShop.status, 403);
  const [encoded, signature] = activation.body.token.split(".");
  const claims = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  claims.status = "suspended";
  const tampered = `${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${signature}`;
  assert.throws(() => verifySignedToken(tampered, env.keys.publicKey), /signature/i);
  assert.equal((await env.request("/v1/status", { body: { ...binding, token: tampered } })).status, 403);
});

test("deactivation releases an installation binding and activation/status events are logged", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", { body: { ...binding, licenseKey: license.licenseKey } });
  await env.request("/v1/status", { body: { ...binding, token: activation.body.token } });
  assert.equal((await env.request("/v1/deactivate", { body: { ...binding, token: activation.body.token } })).status, 200);
  const events = env.service.logs(license.licenseId).map(log => log.event);
  assert.ok(events.includes("activation_succeeded"));
  assert.ok(events.includes("status_check"));
  assert.ok(events.includes("deactivation"));
});

test("status, listing, logs and throttling are exposed only through bounded service endpoints", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  assert.equal((await env.request(`/admin/licenses/${license.licenseId}`, { method: "GET" })).status, 401);
  assert.equal((await env.request(`/admin/licenses/${license.licenseId}`, { method: "GET", admin: true })).body.expiresAt, license.expiresAt);
  assert.equal((await env.request("/admin/licenses", { method: "GET", admin: true })).body.licenses.length, 1);
  const throttled = createLicenseServer({ service: env.service, admins, port: 0, rateLimit: 1 });
  const address = await throttled.listen();
  try {
    const url = `http://127.0.0.1:${address.port}/v1/activate`;
    const request = () => fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    await request();
    assert.equal((await request()).status, 429);
  } finally {
    await throttled.close();
  }
});

test("admin routes enforce roles and record administrator identities for license changes", async t => {
  const env = await fixture(t);
  assert.equal((await env.request("/admin/licenses", { method: "GET" })).status, 401);

  const readOnlyAdmins = [{
    id: "read-only-admin",
    token: crypto.randomBytes(32).toString("base64url"),
    roles: ["licenses:read"]
  }];
  const restricted = createLicenseServer({ service: env.service, admins: readOnlyAdmins, port: 0 });
  const address = await restricted.listen();
  try {
    const url = `http://127.0.0.1:${address.port}/admin/shops`;
    const denied = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${readOnlyAdmins[0].token}`
      },
      body: JSON.stringify({ shopName: "Denied Store", planId: "monthly" })
    });
    assert.equal(denied.status, 403);
  } finally {
    await restricted.close();
  }

  const license = await env.createLicense();
  await env.request(`/admin/licenses/${license.licenseId}/renew`, { admin: true });
  await env.request(`/admin/licenses/${license.licenseId}/suspend`, { admin: true });
  await env.request(`/admin/licenses/${license.licenseId}/reactivate`, { admin: true });
  const changes = env.service.logs(license.licenseId)
    .filter(log => ["license_created", "renewal", "suspended", "reactivated"].includes(log.event));
  assert.deepEqual(changes.map(log => log.actorId), Array(changes.length).fill("test-admin"));
  assert.equal(changes.length, 4);
});

test("license records and audit history persist across a server restart", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  await env.request(`/admin/licenses/${license.licenseId}/suspend`, { admin: true });
  await env.restartServer();

  assert.equal(env.service.list().length, 1);
  assert.equal(env.service.view(license.licenseId).status, "suspended");
  assert.ok(env.service.logs(license.licenseId).some(log => log.event === "suspended" && log.actorId === "test-admin"));
});

test("admin dashboard requires an authenticated CSRF-protected session", async t => {
  const env = await fixture(t);
  const page = await fetch(`${env.url}/admin/`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy"), /default-src 'self'/);
  assert.match(await page.text(), /ShopPOS Admin/);
  const dashboardScript = await fetch(`${env.url}/admin/app.js`);
  assert.equal(dashboardScript.status, 200);
  assert.match(await dashboardScript.text(), /Generate license key/);
  const dashboardStyles = await fetch(`${env.url}/admin/styles.css`);
  assert.equal(dashboardStyles.status, 200);
  assert.match(await dashboardStyles.text(), /--gold/);

  const wrongOrigin = await fetch(`${env.url}/admin/session`, {
    method: "POST",
    headers: { origin: "http://attacker.example", authorization: "Bearer invalid" }
  });
  assert.equal(wrongOrigin.status, 403);

  const unauthorized = await env.request("/admin/session", {
    method: "POST",
    headers: { origin: env.url, authorization: "Bearer invalid" }
  });
  assert.equal(unauthorized.status, 401);

  const login = await fetch(`${env.url}/admin/session`, {
    method: "POST",
    headers: { origin: env.url, authorization: `Bearer ${ADMIN_TOKEN}` }
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie");
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Path=\/admin/);
  const session = await login.json();
  assert.equal(session.administrator.id, "test-admin");
  assert.ok(session.csrfToken);

  const cookieHeader = cookie.split(";")[0];
  const dashboardData = await fetch(`${env.url}/admin/dashboard`, { headers: { cookie: cookieHeader } });
  assert.equal(dashboardData.status, 200);
  const missingCsrf = await fetch(`${env.url}/admin/plans`, {
    method: "PUT",
    headers: {
      origin: env.url,
      cookie: cookieHeader,
      "content-type": "application/json"
    },
    body: JSON.stringify({ id: "trial", name: "Trial", interval: "monthly", priceMinor: 0, currency: "USD" })
  });
  assert.equal(missingCsrf.status, 403);
  const logout = await fetch(`${env.url}/admin/session`, {
    method: "DELETE",
    headers: { origin: env.url, cookie: cookieHeader, "x-csrf-token": session.csrfToken }
  });
  assert.equal(logout.status, 204);
  const loggedOut = await fetch(`${env.url}/admin/dashboard`, { headers: { cookie: cookieHeader } });
  assert.equal(loggedOut.status, 401);

  const secureServer = createLicenseServer({ service: env.service, admins, port: 0, secureCookies: true });
  const secureAddress = await secureServer.listen();
  try {
    const secureUrl = `http://127.0.0.1:${secureAddress.port}`;
    const secureLogin = await fetch(`${secureUrl}/admin/session`, {
      method: "POST",
      headers: { origin: secureUrl, authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    assert.equal(secureLogin.status, 200);
    assert.match(secureLogin.headers.get("set-cookie"), /; Secure(?:;|$)/);
  } finally {
    await secureServer.close();
  }
});

test("admin login rate-limits repeated invalid credentials", async t => {
  const env = await fixture(t);
  const responses = [];
  for (let attempt = 0; attempt < 6; attempt += 1) {
    responses.push(await fetch(`${env.url}/admin/session`, {
      method: "POST",
      headers: { origin: env.url, authorization: "Bearer invalid" }
    }));
  }
  assert.deepEqual(responses.slice(0, 5).map(response => response.status), Array(5).fill(401));
  assert.equal(responses[5].status, 429);
});

test("existing ShopPOS shops register once and receive one-time bound license keys", async t => {
  const env = await fixture(t);
  const localShopId = "ae6def4e-8562-4205-a9f8-674d56b4e885";
  const registered = await env.request("/admin/shops/register", {
    body: { localShopId, confirmationShopId: localShopId, shopName: "Existing Corner Shop" },
    admin: true
  });
  assert.equal(registered.status, 201);
  assert.equal(registered.body.localShopId, localShopId);
  assert.equal(registered.body.verifiedBy, "test-admin");

  const duplicate = await env.request("/admin/shops/register", {
    body: { localShopId, confirmationShopId: localShopId, shopName: "Duplicate Shop" },
    admin: true
  });
  assert.equal(duplicate.status, 400);

  const mismatch = await env.request(`/admin/shops/${registered.body.id}/licenses`, {
    body: { confirmedLocalShopId: crypto.randomUUID(), planId: "monthly" },
    admin: true
  });
  assert.equal(mismatch.status, 400);

  const issue = await env.request(`/admin/shops/${registered.body.id}/licenses`, {
    body: { confirmedLocalShopId: localShopId, planId: "monthly" },
    admin: true
  });
  assert.equal(issue.status, 201);
  assert.match(issue.body.licenseKey, /^SP-/);
  assert.equal(issue.body.intendedLocalShopId, localShopId);
  const storedHash = env.service.query("SELECT key_hash FROM licenses WHERE id = ?", [issue.body.licenseId]).key_hash;
  assert.equal(storedHash, crypto.createHash("sha256").update(issue.body.licenseKey).digest("hex"));
  assert.equal(storedHash.includes(issue.body.licenseKey), false);
  const licenseList = await env.request("/admin/licenses", { method: "GET", admin: true });
  assert.equal(licenseList.status, 200);
  assert.equal(licenseList.body.licenses.length, 1);
  assert.equal("licenseKey" in licenseList.body.licenses[0], false);

  const wrongShop = await env.request("/v1/activate", {
    body: { licenseKey: issue.body.licenseKey, localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() }
  });
  assert.equal(wrongShop.status, 403);

  const deviceId = crypto.randomUUID();
  const activation = await env.request("/v1/activate", {
    body: { licenseKey: issue.body.licenseKey, localShopId, deviceId }
  });
  assert.equal(activation.status, 200);
  const reused = await env.request("/v1/activate", {
    body: { licenseKey: issue.body.licenseKey, localShopId, deviceId }
  });
  assert.equal(reused.status, 403);
  assert.ok(env.service.logs(issue.body.licenseId).some(log => log.event === "activation_succeeded"));
  assert.ok(env.service.logs(issue.body.licenseId).some(log => log.event === "activation_failed" && log.detail === "key_already_redeemed"));
  assert.ok(env.service.logs().some(log => log.event === "shop_registered" && log.actorId === "test-admin"));

  const concurrentIssue = await env.request(`/admin/shops/${registered.body.id}/licenses`, {
    body: { confirmedLocalShopId: localShopId, planId: "monthly" },
    admin: true
  });
  const attempts = await Promise.all([0, 1].map(() => env.request("/v1/activate", {
    body: { licenseKey: concurrentIssue.body.licenseKey, localShopId, deviceId: crypto.randomUUID() }
  })));
  assert.deepEqual(attempts.map(result => result.status).sort(), [200, 403]);
});

test("admin can configure only supported plans and custom license expiry", async t => {
  const env = await fixture(t);
  const incorrectConfirmation = await env.request("/admin/shops/register", {
    body: {
      localShopId: crypto.randomUUID(),
      confirmationShopId: crypto.randomUUID(),
      shopName: "Expiry Test"
    },
    admin: true
  });
  assert.equal(incorrectConfirmation.status, 400);

  const localShopId = crypto.randomUUID();
  const shop = await env.request("/admin/shops/register", {
    body: { localShopId, confirmationShopId: localShopId, shopName: "Expiry Test" },
    admin: true
  });
  const unsupportedLifetime = await env.request("/admin/plans", {
    method: "PUT",
    body: { id: "lifetime", name: "Lifetime", interval: "lifetime", priceMinor: 0, currency: "USD", available: true },
    admin: true
  });
  assert.equal(unsupportedLifetime.status, 400);
  const plan = await env.request("/admin/plans", {
    method: "PUT",
    body: { id: "custom-term", name: "Custom term", interval: "monthly", priceMinor: 10000, currency: "USD", trialDays: 0, graceDays: 1, available: true },
    admin: true
  });
  assert.equal(plan.status, 200);
  const expiresAt = "2026-03-01T00:00:00.000Z";
  const license = await env.request(`/admin/shops/${shop.body.id}/licenses`, {
    body: { confirmedLocalShopId: localShopId, planId: "custom-term", expiresAt },
    admin: true
  });
  assert.equal(license.status, 201);
  assert.equal(license.body.expiresAt, expiresAt);
  assert.ok(env.service.logs().some(log => log.event === "plan_updated" && log.actorId === "test-admin" && log.detail === "custom-term"));
  await env.restartServer();
  assert.equal(env.service.plans.get("custom-term").interval, "monthly");
  assert.equal(env.service.view(license.body.licenseId).expiresAt, expiresAt);
});

test("licensee can submit a manual payment for their monthly subscription", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });
  assert.equal(activation.status, 200);

  const submitted = await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "INV-2026-001",
      note: "January subscription"
    }
  });
  assert.equal(submitted.status, 200);
  assert.equal(submitted.body.status, "pending");
  assert.equal(submitted.body.method, "manual");
  assert.equal(submitted.body.planId, "monthly");
  assert.equal(submitted.body.amountMinor, 4200);
  assert.equal(submitted.body.currency, "USD");
  assert.equal(submitted.body.reference, "INV-2026-001");
});

test("licensee cannot submit payment with wrong amount, plan, or reference", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });
  assert.equal(activation.status, 200);

  const wrongAmount = await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      reference: "INV-2026-002",
      amountMinor: 100
    }
  });
  assert.equal(wrongAmount.status, 400);

  const wrongPlan = await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "yearly",
      amountMinor: 40000,
      reference: "INV-2026-003"
    }
  });
  assert.equal(wrongPlan.status, 400);

  const shortRef = await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      reference: "abc"
    }
  });
  assert.equal(shortRef.status, 400);
});

test("licensee can only view their own payments", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });
  assert.equal(activation.status, 200);

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "INV-2026-004"
    }
  });

  const payments = await env.request(`/v1/payments?token=${encodeURIComponent(activation.body.token)}&localShopId=${encodeURIComponent(binding.localShopId)}&deviceId=${encodeURIComponent(binding.deviceId)}`, {
    method: "GET"
  });
  assert.equal(payments.status, 200);
  assert.equal(payments.body.payments.length, 1);
  assert.equal(payments.body.payments[0].reference, "INV-2026-004");

  const wrongDevice = await env.request(`/v1/payments?token=${encodeURIComponent(activation.body.token)}&localShopId=${encodeURIComponent(binding.localShopId)}&deviceId=${crypto.randomUUID()}`, {
    method: "GET"
  });
  assert.equal(wrongDevice.status, 403);
});

test("admin can list and view payments", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "INV-ADMIN-001"
    }
  });

  const listed = await env.request("/admin/payments", {
    method: "GET",
    admin: true
  });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.payments.length, 1);
  assert.equal(listed.body.payments[0].reference, "INV-ADMIN-001");
  assert.equal(listed.body.payments[0].status, "pending");

  const paymentId = listed.body.payments[0].id;
  const viewed = await env.request(`/admin/payments/${paymentId}`, {
    method: "GET",
    admin: true
  });
  assert.equal(viewed.status, 200);
  assert.equal(viewed.body.id, paymentId);
});

test("admin can approve a pending payment and renew the subscription", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });
  assert.equal(activation.status, 200);

  env.service.db.run("UPDATE licenses SET expires_at = ? WHERE id = ?", [
    "2026-01-01T12:00:00.000Z", license.licenseId
  ]);

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "INV-APPROVE-001"
    }
  });

  const listed = await env.request("/admin/payments", {
    method: "GET",
    admin: true
  });
  const paymentId = listed.body.payments[0].id;

  const before = env.service.view(license.licenseId);
  assert.ok(["expired", "grace_period"].includes(before.status));

  const approved = await env.request(`/admin/payments/${paymentId}/approve`, {
    method: "POST",
    body: {},
    admin: true
  });
  assert.equal(approved.status, 200);
  assert.equal(approved.body.payment.status, "approved");
  assert.ok(approved.body.license.expiresAt > "2026-01-01T12:00:00.000Z");
});

test("duplicate payment approval is prevented", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "INV-DUP-001"
    }
  });

  const listed = await env.request("/admin/payments", {
    method: "GET",
    admin: true
  });
  const paymentId = listed.body.payments[0].id;

  const first = await env.request(`/admin/payments/${paymentId}/approve`, {
    method: "POST",
    body: {},
    admin: true
  });
  assert.equal(first.status, 200);

  const second = await env.request(`/admin/payments/${paymentId}/approve`, {
    method: "POST",
    body: {},
    admin: true
  });
  assert.equal(second.status, 400);
  assert.match(second.body.error, /already decided|already approved/i);
});

test("admin can reject a pending payment with a reason", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "INV-REJECT-001"
    }
  });

  const listed = await env.request("/admin/payments", {
    method: "GET",
    admin: true
  });
  const paymentId = listed.body.payments[0].id;

  const rejected = await env.request(`/admin/payments/${paymentId}/reject`, {
    method: "POST",
    body: { reason: "Insufficient funds" },
    admin: true
  });
  assert.equal(rejected.status, 200);
  assert.equal(rejected.body.status, "rejected");
  assert.equal(rejected.body.decisionReason, "Insufficient funds");

  const retry = await env.request(`/admin/payments/${paymentId}/reject`, {
    method: "POST",
    body: { reason: "Still insufficient" },
    admin: true
  });
  assert.equal(retry.status, 400);
});

test("webhook accepts valid signed test gateway event", async t => {
  const secret = "test-webhook-secret-key-that-is-exactly-thirty-two";
  process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET = secret;
  t.after(() => { delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET; });

  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "WEBHOOK-001"
    }
  });

  const timestamp = String(Date.now());
  const payload = {
    eventId: "evt_webhook_001",
    eventType: "payment.succeeded",
    transactionId: "txn_webhook_001",
    amountMinor: 4200,
    currency: "USD",
    status: "succeeded",
    customerReference: "WEBHOOK-001"
  };
  const rawBody = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), Buffer.from(rawBody, "utf8")]))
    .digest("hex");

  const response = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: payload,
    headers: {
      "content-type": "application/json",
      "x-shoppos-test-signature": signature,
      "x-shoppos-test-timestamp": timestamp
    }
  });
  assert.equal(response.status, 200);
  assert.ok(response.body.accepted);
  assert.equal(response.body.applied, true);
});

test("webhook rejects invalid signature", async t => {
  const secret = "test-webhook-secret-key-that-is-exactly-thirty-two";
  process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET = secret;
  t.after(() => { delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET; });

  const env = await fixture(t);

  const timestamp = String(Date.now());
  const payload = {
    eventId: "evt_webhook_bad_001",
    eventType: "payment.succeeded",
    transactionId: "txn_webhook_bad_001",
    amountMinor: 4200,
    currency: "USD",
    status: "succeeded",
    customerReference: "NOPE-001"
  };

  const response = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: payload,
    headers: {
      "content-type": "application/json",
      "x-shoppos-test-signature": "invalid-signature-hex",
      "x-shoppos-test-timestamp": timestamp
    }
  });
  assert.equal(response.status, 401);
  assert.match(response.body.error, /signature/i);
});

test("webhook replay is idempotent for same event id", async t => {
  const secret = "test-webhook-secret-key-that-is-exactly-thirty-two";
  process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET = secret;
  t.after(() => { delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET; });

  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "WEBHOOK-IDEMP-001"
    }
  });

  const timestamp = String(Date.now());
  const payload = {
    eventId: "evt_webhook_idemp_001",
    eventType: "payment.succeeded",
    transactionId: "txn_webhook_idemp_001",
    amountMinor: 4200,
    currency: "USD",
    status: "succeeded",
    customerReference: "WEBHOOK-IDEMP-001"
  };
  const rawBody = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), Buffer.from(rawBody, "utf8")]))
    .digest("hex");

  const headers = {
    "content-type": "application/json",
    "x-shoppos-test-signature": signature,
    "x-shoppos-test-timestamp": timestamp
  };

  const first = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: payload,
    headers
  });
  assert.equal(first.status, 200);
  assert.equal(first.body.applied, true);

  const second = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: payload,
    headers
  });
  assert.equal(second.status, 200);
  assert.equal(second.body.duplicate, true);
  assert.equal(second.body.applied, false);
});

test("admin payment routes require manage role for state changes", async t => {
  const env = await fixture(t);
  const readOnlyToken = crypto.randomBytes(32).toString("base64url");
  const readOnlyAdmins = [{
    id: "read-only-admin",
    token: readOnlyToken,
    roles: ["licenses:read"]
  }];
  const restricted = createLicenseServer({ service: env.service, admins: readOnlyAdmins, port: 0 });
  const address = await restricted.listen();
  try {
    const url = `http://127.0.0.1:${address.port}`;
    // Read-only admin can list payments (licenses:read)
    const listed = await fetch(`${url}/admin/payments`, {
      method: "GET",
      headers: { authorization: `Bearer ${readOnlyToken}` }
    });
    assert.equal(listed.status, 200);
    // Read-only admin cannot approve (licenses:manage required)
    const denied = await fetch(`${url}/admin/payments/${crypto.randomUUID()}/approve`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${readOnlyToken}`,
        "content-type": "application/json"
      },
      body: "{}"
    });
    assert.equal(denied.status, 403);
  } finally {
    await restricted.close();
  }
});

test("approval applies renewal exactly once", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  env.service.db.run("UPDATE licenses SET expires_at = ? WHERE id = ?", [
    "2026-01-01T12:00:00.000Z", license.licenseId
  ]);

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "INV-ONCE-001"
    }
  });

  const listed = await env.request("/admin/payments", {
    method: "GET",
    admin: true
  });
  const paymentId = listed.body.payments[0].id;

  const before = env.service.view(license.licenseId);
  assert.ok(["expired", "grace_period"].includes(before.status));

  const approved = await env.request(`/admin/payments/${paymentId}/approve`, {
    method: "POST",
    body: {},
    admin: true
  });
  assert.equal(approved.status, 200);
  assert.ok(approved.body.license.expiresAt > "2026-01-01T12:00:00.000Z");

  const renewedView = env.service.view(license.licenseId);
  const firstExpiry = renewedView.expiresAt;

  const second = await env.request(`/admin/payments/${paymentId}/approve`, {
    method: "POST",
    body: {},
    admin: true
  });
  assert.equal(second.status, 400);

  const stillSame = env.service.view(license.licenseId);
  assert.equal(stillSame.expiresAt, firstExpiry);
});

test("webhook applies failed payment status exactly once", async t => {
  const secret = "test-webhook-secret-key-that-is-exactly-thirty-two";
  process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET = secret;
  t.after(() => { delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET; });

  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "WEBHOOK-FAIL-001"
    }
  });

  const timestamp = String(Date.now());
  const payload = {
    eventId: "evt_webhook_fail_001",
    eventType: "payment.failed",
    transactionId: "txn_webhook_fail_001",
    amountMinor: 4200,
    currency: "USD",
    status: "failed",
    customerReference: "WEBHOOK-FAIL-001"
  };
  const rawBody = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), Buffer.from(rawBody, "utf8")]))
    .digest("hex");

  const response = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: payload,
    headers: {
      "content-type": "application/json",
      "x-shoppos-test-signature": signature,
      "x-shoppos-test-timestamp": timestamp
    }
  });
  assert.equal(response.status, 200);
  assert.ok(response.body.accepted);
  // A failed payment does not renew the subscription; applied should be false.
  assert.equal(response.body.applied, false);

  const listed = await env.request("/admin/payments", {
    method: "GET",
    admin: true
  });
  const payment = listed.body.payments.find(p => p.reference === "WEBHOOK-FAIL-001");
  assert.equal(payment.status, "failed");
});

test("webhook rejects unknown provider", async t => {
  const env = await fixture(t);

  const response = await env.request("/v1/webhooks/gateway/nonexistent-provider", {
    method: "POST",
    body: {},
    headers: { "content-type": "application/json" }
  });
  assert.equal(response.status, 400);
});

test("webhook config error returns 500 without exposing secret", async t => {
  delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET;

  const env = await fixture(t);

  const response = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: {},
    headers: { "content-type": "application/json" }
  });
  assert.equal(response.status, 500);
  assert.ok(!/secret|PAYMENT_GATEWAY/i.test(response.body.error), "Error should not expose secret info");
});

test("webhook rejects timestamp outside skew window", async t => {
  const secret = "test-webhook-secret-key-that-is-exactly-thirty-two";
  process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET = secret;
  t.after(() => { delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET; });

  const env = await fixture(t);

  // Use a timestamp from 10 minutes ago (outside 5-minute skew window)
  const oldTimestamp = String(Date.now() - 10 * 60 * 1000);
  const payload = {
    eventId: "evt_webhook_stale_001",
    eventType: "payment.succeeded",
    transactionId: "txn_webhook_stale_001",
    amountMinor: 4200,
    currency: "USD",
    status: "succeeded",
    customerReference: "STALE-001"
  };
  const rawBody = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${oldTimestamp}.`, "utf8"), Buffer.from(rawBody, "utf8")]))
    .digest("hex");

  const response = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: payload,
    headers: {
      "content-type": "application/json",
      "x-shoppos-test-signature": signature,
      "x-shoppos-test-timestamp": oldTimestamp
    }
  });
  assert.equal(response.status, 401);
});

test("webhook rejects missing timestamp header", async t => {
  const secret = "test-webhook-secret-key-that-is-exactly-thirty-two";
  process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET = secret;
  t.after(() => { delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET; });

  const env = await fixture(t);

  const response = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: {},
    headers: {
      "content-type": "application/json",
      "x-shoppos-test-signature": "some-signature"
    }
  });
  assert.equal(response.status, 401);
});

test("gateway adapter interface exposes test adapter only", () => {
  const { getGatewayAdapter, listGatewayAdapters } = require("./payments-gateway.cjs");
  const adapters = listGatewayAdapters();
  assert.equal(adapters.length, 1);
  assert.equal(adapters[0], "test");

  const testAdapter = getGatewayAdapter("test");
  assert.ok(testAdapter);
  assert.equal(testAdapter.id, "test");
  assert.equal(testAdapter.sandboxOnly, true);
  assert.equal(testAdapter.canEnableInProduction(), false);
  assert.ok(typeof testAdapter.describe === "function");
  assert.ok(typeof testAdapter.verifyWebhook === "function");

  const unknownAdapter = getGatewayAdapter("stripe");
  assert.equal(unknownAdapter, undefined);
});

test("webhook amount/currency mismatch does not renew subscription", async t => {
  const secret = "test-webhook-secret-key-that-is-exactly-thirty-two";
  process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET = secret;
  t.after(() => { delete process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET; });

  const env = await fixture(t);
  const license = await env.createLicense();
  const binding = { localShopId: crypto.randomUUID(), deviceId: crypto.randomUUID() };
  const activation = await env.request("/v1/activate", {
    body: { ...binding, licenseKey: license.licenseKey }
  });

  // Expire the license so a successful webhook would renew it
  env.service.db.run("UPDATE licenses SET expires_at = ? WHERE id = ?", [
    "2026-01-01T12:00:00.000Z", license.licenseId
  ]);

  await env.request("/v1/payments/submit", {
    body: {
      token: activation.body.token,
      localShopId: binding.localShopId,
      deviceId: binding.deviceId,
      planId: "monthly",
      amountMinor: 4200,
      currency: "USD",
      reference: "WEBHOOK-MISMATCH-001"
    }
  });

  const before = env.service.view(license.licenseId);
  assert.ok(["expired", "grace_period"].includes(before.status));

  const timestamp = String(Date.now());
  // Send amount that doesn't match plan price
  const payload = {
    eventId: "evt_webhook_mismatch_001",
    eventType: "payment.succeeded",
    transactionId: "txn_webhook_mismatch_001",
    amountMinor: 999999,
    currency: "USD",
    status: "succeeded",
    customerReference: "WEBHOOK-MISMATCH-001"
  };
  const rawBody = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), Buffer.from(rawBody, "utf8")]))
    .digest("hex");

  const response = await env.request("/v1/webhooks/gateway/test", {
    method: "POST",
    body: payload,
    headers: {
      "content-type": "application/json",
      "x-shoppos-test-signature": signature,
      "x-shoppos-test-timestamp": timestamp
    }
  });
  assert.equal(response.status, 200);
  assert.ok(response.body.accepted);
  assert.equal(response.body.applied, false);

  // License should NOT be renewed due to amount mismatch
  const view = env.service.view(license.licenseId);
  assert.ok(["expired", "grace_period"].includes(view.status));
});

test("health-check endpoint returns service status", async t => {
  const env = await fixture(t);
  const response = await fetch(`${env.url}/v1/health`, { method: "GET" });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, "ok");
  assert.equal(body.service, "shoppos-license-server");
  assert.equal(body.schemaVersion, 4);
});

test("license server can create and list backups", async t => {
  const env = await fixture(t);
  const backupDir = path.join(os.tmpdir(), `shoppos-backup-test-${crypto.randomUUID()}`);

  // Call service method directly to verify backup creation works
  const direct = env.service.createBackup(backupDir);
  assert.ok(direct.backupPath);
  assert.ok(direct.backupFile);
  assert.match(direct.backupFile, /shoppos-license-backup-.*\.sqlite$/);

  // Verify backup file exists and is valid via direct service call
  const fs = require("node:fs");
  assert.ok(fs.existsSync(direct.backupPath));
  const verifyResult = await env.service.verifyBackup(direct.backupPath);
  assert.ok(verifyResult.valid);
  assert.equal(verifyResult.schemaVersion, 4);

  // Clean up
  try { fs.rmSync(backupDir, { recursive: true, force: true }); } catch {}
});

test("license server can restore from backup with pre-restore safety", async t => {
  const env = await fixture(t);
  const license = await env.createLicense();
  const licenseCountBefore = env.service.list().length;

  // Create a backup directly via service
  const backupDir = path.join(os.tmpdir(), `shoppos-restore-test-${crypto.randomUUID()}`);
  const direct = env.service.createBackup(backupDir);

  // Make a change: suspend a license
  const suspendResp = await env.request(`/admin/licenses/${license.licenseId}/suspend`, {
    method: "POST",
    body: {},
    admin: true
  });
  if (suspendResp.status !== 200) console.log("SUSPEND ERROR:", JSON.stringify(suspendResp.body));
  assert.equal(suspendResp.status, 200);
  assert.equal(env.service.view(license.licenseId).status, "suspended");

  // Restore from backup via HTTP API
  const restored = await env.request("/admin/restore", {
    method: "POST",
    body: { backupPath: direct.backupPath },
    admin: true,
    headers: { "content-type": "application/json" }
  });
  if (restored.status !== 200) console.log("RESTORE ERROR:", JSON.stringify(restored.body));
  assert.equal(restored.status, 200);
  assert.ok(restored.body.restored);
  assert.ok(restored.body.preRestoreBackup);

  // Verify the change was reverted
  assert.equal(env.service.view(license.licenseId).status, "active");
  assert.equal(env.service.list().length, licenseCountBefore);

  // Clean up
  try { fs.rmSync(backupDir, { recursive: true, force: true }); } catch {}
});

test("backup routes require manage role", async t => {
  const env = await fixture(t);
  const readOnlyToken = crypto.randomBytes(32).toString("base64url");
  const readOnlyAdmins = [{
    id: "read-only-admin",
    token: readOnlyToken,
    roles: ["licenses:read"]
  }];
  const restricted = createLicenseServer({ service: env.service, admins: readOnlyAdmins, port: 0 });
  const address = await restricted.listen();
  try {
    const url = `http://127.0.0.1:${address.port}`;
    const denied = await fetch(`${url}/admin/backup`, {
      method: "GET",
      headers: { authorization: `Bearer ${readOnlyToken}` }
    });
    assert.equal(denied.status, 403);
  } finally {
    await restricted.close();
  }
});

test("restore rejects missing or invalid backup path", async t => {
  const env = await fixture(t);

  const missing = await env.request("/admin/restore", {
    method: "POST",
    body: {},
    admin: true,
    headers: { "content-type": "application/json" }
  });
  assert.equal(missing.status, 400);

  const invalid = await env.request("/admin/restore", {
    method: "POST",
    body: { backupPath: "/nonexistent/backup.sqlite" },
    admin: true,
    headers: { "content-type": "application/json" }
  });
  assert.equal(invalid.status, 400);
});
