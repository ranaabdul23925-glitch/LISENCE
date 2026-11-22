"use strict";

const crypto = require("node:crypto");
const { createLicenseServer, parseAdminUsers } = require("../license-server.cjs");
const { classifyPostgresError, createDatabase } = require("./database.cjs");
const { PostgresLicenseService, parsePlans, SUBSCRIPTION_GRACE_DAYS } = require("./service.cjs");
const { parseTrustedPublicKeys } = require("../signing-keys.cjs");

function parseIntegerSetting(value, label, defaultValue, min, max) {
  const text = value === undefined || value === "" ? String(defaultValue) : String(value);
  if (!/^(0|[1-9]\d*)$/.test(text)) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}.`);
  }
  return parsed;
}

function validatePostgresConfiguration(env = process.env) {
  const connectionString = env.SHOPPOS_DATABASE_URL?.trim();
  if (!connectionString) throw new Error("SHOPPOS_DATABASE_URL is required for PostgreSQL.");
  let databaseUrl;
  try {
    databaseUrl = new URL(connectionString);
  } catch {
    throw new Error("SHOPPOS_DATABASE_URL must be a valid PostgreSQL connection URL.");
  }
  if (!["postgres:", "postgresql:"].includes(databaseUrl.protocol)) {
    throw new Error("SHOPPOS_DATABASE_URL must use the PostgreSQL protocol.");
  }

  const privateKey = env.LICENSE_SIGNING_PRIVATE_KEY?.replace(/\\n/g, "\n");
  if (!privateKey || /replace-with/i.test(privateKey)) {
    throw new Error("Set LICENSE_SIGNING_PRIVATE_KEY to a server-only Ed25519 PKCS#8 private key.");
  }
  let key;
  try {
    key = crypto.createPrivateKey(privateKey);
  } catch (error) {
    const validationError = new Error(
      "LICENSE_SIGNING_PRIVATE_KEY must be a valid Ed25519 PKCS#8 private key.",
      { cause: error }
    );
    validationError.startupStage = "signing_key_validation";
    throw validationError;
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("LICENSE_SIGNING_PRIVATE_KEY must be an Ed25519 private key.");
  }
  const trustedPublicKeys = parseTrustedPublicKeys(
    env.LICENSE_TRUSTED_PUBLIC_KEYS_JSON,
    crypto.createPublicKey(key)
  );

  const plans = parsePlans(env.LICENSE_PLANS_JSON);
  const admins = parseAdminUsers(env.LICENSE_ADMIN_USERS_JSON);
  const production = env.NODE_ENV === "production";
  for (const plan of plans.values()) {
    if (production && plan.graceDays !== SUBSCRIPTION_GRACE_DAYS) {
      throw new Error(`Production plan ${plan.id} must have a grace period of exactly ${SUBSCRIPTION_GRACE_DAYS} days.`);
    }
  }

  const host = env.LICENSE_HOST?.trim() || (production ? "0.0.0.0" : "127.0.0.1");
  if (host.length > 253 || /[\s/\\]/.test(host)) {
    throw new Error("LICENSE_HOST must be a valid bind address or hostname.");
  }
  const port = parseIntegerSetting(env.LICENSE_PORT?.trim() || env.PORT, "LICENSE_PORT or PORT", 8787, 1, 65535);
  const offlineGraceDays = parseIntegerSetting(
    env.LICENSE_OFFLINE_GRACE_DAYS,
    "LICENSE_OFFLINE_GRACE_DAYS",
    7,
    0,
    90
  );
  return {
    connectionString,
    privateKey,
    trustedPublicKeys,
    plans,
    admins,
    host,
    port,
    offlineGraceDays,
    production
  };
}

async function createPostgresService(configuration, { database } = {}) {
  const ownsDatabase = !database;
  return PostgresLicenseService.create({
    database: database ?? createDatabase(configuration.connectionString),
    closeOnInitializationFailure: ownsDatabase,
    plans: [...configuration.plans.values()],
    privateKey: configuration.privateKey,
    trustedPublicKeys: configuration.trustedPublicKeys,
    offlineGraceDays: configuration.offlineGraceDays,
    requireFixedGrace: configuration.production
  });
}

async function startPostgresServer(env = process.env) {
  const configuration = validatePostgresConfiguration(env);
  const service = await createPostgresService(configuration);
  const instance = createLicenseServer({
    service,
    admins: configuration.admins,
    host: configuration.host,
    port: configuration.port,
    secureCookies: env.NODE_ENV === "production"
  });
  try {
    await instance.listen();
  } catch (error) {
    await service.close();
    throw error;
  }

  console.log(`ShopPOS PostgreSQL license server listening on ${configuration.host}:${configuration.port}`);
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      await instance.close();
      await service.close();
      process.exitCode = 0;
    } catch (error) {
      console.error("ShopPOS license server shutdown failed.", {
        category: classifyPostgresError(error)
      });
      process.exitCode = 1;
    }
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  return { service, instance };
}

if (require.main === module) {
  startPostgresServer().catch(error => {
    console.error("ShopPOS PostgreSQL license server could not start.", {
      category: classifyPostgresError(error)
    });
    process.exitCode = 1;
  });
}

module.exports = {
  createPostgresService,
  parseIntegerSetting,
  startPostgresServer,
  validatePostgresConfiguration
};
