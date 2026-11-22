"use strict";

// ShopPOS license server -- PostgreSQL startup entry point.
//
// Opt-in production entry point that stores license data in PostgreSQL via
// node-postgres. The default `npm start` path still uses the sql.js/SQLite
// service unchanged. This file is never run by the desktop application.
//
// Configuration (environment, never CLI arguments):
//   POSTGRES_DATABASE_URL       required. postgresql:// connection string.
//   LICENSE_SIGNING_PRIVATE_KEY required. Ed25519 PKCS#8 private key (server-only).
//   LICENSE_PLANS_JSON          required. JSON array of subscription plans.
//   LICENSE_ADMIN_USERS_JSON    required. JSON array of admin tokens + roles.
//   LICENSE_HOST                optional. Bind address (default 127.0.0.1).
//   LICENSE_PORT / PORT         optional. Bind port (default 8787).
//   LICENSE_OFFLINE_GRACE_DAYS  optional. 0-90 (default 7).
//   LICENSE_TRUST_PROXY         optional. false | true | comma-separated IPs/CIDRs.
//
// The server does not auto-load .env files. Export variables in the process
// environment (or a systemd EnvironmentFile) before starting.
//
// Graceful shutdown: SIGINT/SIGTERM stop accepting new connections, close the
// HTTP server, then end the PostgreSQL pool.

const {
  validatePostgresServerConfiguration
} = require("./license-server.cjs");
const { createPostgresLicenseServer } = require("./postgres-adapter.cjs");

async function startPostgresFromEnvironment(env = process.env) {
  const config = validatePostgresServerConfiguration(env);
  const instance = await createPostgresLicenseServer({
    databaseUrl: config.databaseUrl,
    plans: [...config.plans.values()],
    privateKey: config.privateKey,
    offlineGraceDays: config.offlineGraceDays,
    admins: config.admins,
    host: config.host,
    port: config.port,
    secureCookies: env.NODE_ENV === "production",
    trustProxy: config.trustProxy
  });

  await instance.listen();
  const address = instance.server.address();
  const displayPort = typeof address === "object" && address ? address.port : config.port;
  console.log(`ShopPOS license server (PostgreSQL) listening on ${config.host}:${displayPort}`);

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`ShopPOS license server received ${signal}; shutting down.`);
    try {
      await instance.close();
    } catch (error) {
      console.error("Error while closing the HTTP server:", error);
    }
    try {
      await instance.service.close();
    } catch (error) {
      console.error("Error while closing the PostgreSQL pool:", error);
    }
    process.exit(0);
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));

  return instance;
}

if (require.main === module) {
  startPostgresFromEnvironment().catch(error => {
    console.error("ShopPOS PostgreSQL license server could not start:", error);
    process.exitCode = 1;
  });
}

module.exports = { startPostgresFromEnvironment };