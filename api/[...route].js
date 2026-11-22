"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const {
  authenticateAdmin,
  createLicenseRequestHandler,
  parseAdminUsers
} = require("../license-server.cjs");
const { createPostgresService, validatePostgresConfiguration } = require("../postgres/server.cjs");
const { createDatabase, getPostgresErrorDiagnostic } = require("../postgres/database.cjs");

// TEMPORARY: remove this authenticated diagnostic route after production key validation.
const TEMPORARY_SIGNING_KEY_DIAGNOSTIC_PATH = "/api/admin/temporary/signing-key-diagnostic";
let handlerPromise;
let lastStartupFailure;
const STARTUP_STAGES = new Set([
  "configuration_validation",
  "signing_key_validation",
  "service_construction",
  "schema_table_validation",
  "schema_column_validation",
  "support_table_initialization",
  "plan_seeding",
  "plan_loading",
  "plan_validation",
  "request_handler_creation",
  "service_health_check"
]);
const CONFIGURATION_STAGES = new Set([
  "configuration_validation",
  "signing_key_validation"
]);

function getSafeFailure(error, fallbackStage) {
  const stage = STARTUP_STAGES.has(error && error.startupStage)
    ? error.startupStage
    : fallbackStage;
  const diagnostic = CONFIGURATION_STAGES.has(stage)
    ? { category: "CONFIGURATION_ERROR", certificateCode: null }
    : getPostgresErrorDiagnostic(error);
  return { stage, ...diagnostic };
}

function logFailure(message, error, stage) {
  console.error(message, getSafeFailure(error, stage));
}

function diagnoseSigningKey(value) {
  const variablePresent = typeof value === "string" && value.length > 0;
  const normalizedValue = variablePresent ? value.replace(/\\n/g, "\n") : "";
  const pemMarkersPresent = normalizedValue.includes("-----BEGIN PRIVATE KEY-----") &&
    normalizedValue.includes("-----END PRIVATE KEY-----");
  let key;
  try {
    if (variablePresent) key = crypto.createPrivateKey(normalizedValue);
  } catch {
    key = undefined;
  }
  return {
    containsActualNewline: variablePresent && value.includes("\n"),
    containsEscapedNewline: variablePresent && value.includes("\\n"),
    pemMarkersPresent,
    parseSucceeded: Boolean(key),
    isEd25519: key?.asymmetricKeyType === "ed25519"
  };
}

function handleSigningKeyFormatDiagnostic(request, response, includeAdditionalAdmins = false) {
  let administrators;
  try {
    administrators = parseAdminUsers(process.env.LICENSE_ADMIN_USERS_JSON);
    if (includeAdditionalAdmins) {
      const additionalAdmins = process.env.LICENSE_DIAGNOSTIC_ADMIN_USERS_JSON;
      if (additionalAdmins !== undefined && additionalAdmins !== "") {
        administrators = parseAdminUsers([
          ...administrators,
          ...parseAdminUsers(additionalAdmins)
        ]);
      }
    }
  } catch {
    return responseJson(response, 503, { error: "The temporary diagnostic is unavailable." });
  }

  const administrator = authenticateAdmin(request.headers.authorization, administrators);
  if (!administrator) {
    return responseJson(response, 401, { error: "Administrator authentication required." });
  }
  if (!administrator.roles.includes("licenses:manage")) {
    return responseJson(response, 403, { error: "Administrator role licenses:manage is required." });
  }

  return responseJson(
    response,
    200,
    diagnoseSigningKey(process.env.LICENSE_SIGNING_PRIVATE_KEY)
  );
}

function responseJson(response, status, body) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

async function checkDatabaseConnection() {
  let database;
  let connected = false;
  let errorDiagnostic = { category: null, certificateCode: null };
  try {
    database = createDatabase();
    await database.healthCheck();
    connected = true;
  } catch (error) {
    logFailure("ShopPOS license database health check failed.", error);
    errorDiagnostic = getPostgresErrorDiagnostic(error);
  }
  if (database) {
    try {
      await database.close();
    } catch (error) {
      logFailure("ShopPOS license database health check cleanup failed.", error);
    }
  }
  return {
    status: connected ? "connected" : "unavailable",
    errorCategory: errorDiagnostic.category,
    certificateCode: errorDiagnostic.certificateCode
  };
}

async function handleHealthCheck(response) {
  let serviceStatus = "unavailable";
  let serviceFailure = lastStartupFailure;
  let databaseCheck = { status: "unavailable", errorCategory: null, certificateCode: null };
  try {
    const { service } = await getHandler();
    await service.db.healthCheck();
    serviceStatus = "available";
    serviceFailure = null;
    databaseCheck = { status: "connected", errorCategory: null, certificateCode: null };
  } catch (error) {
    serviceFailure = getSafeFailure(
      error,
      lastStartupFailure ? lastStartupFailure.stage : "service_health_check"
    );
    logFailure("ShopPOS license service health check failed.", error, serviceFailure.stage);
    databaseCheck = await checkDatabaseConnection();
  }

  response.writeHead(serviceStatus === "available" ? 200 : 503, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8"
  });
  response.end(JSON.stringify({
    service: serviceStatus,
    database: databaseCheck.status,
    databaseError: databaseCheck.errorCategory,
    databaseCertificateError: databaseCheck.certificateCode,
    serviceError: serviceFailure && serviceFailure.category,
    serviceFailureStage: serviceFailure && serviceFailure.stage,
    serviceCertificateError: serviceFailure && serviceFailure.certificateCode
  }));
}

async function getHandler() {
  if (!handlerPromise) {
    let stage = "configuration_validation";
    handlerPromise = (async () => {
      const configuration = validatePostgresConfiguration(process.env);
      stage = "service_construction";
      const service = await createPostgresService(configuration);
      stage = "request_handler_creation";
      const handler = createLicenseRequestHandler({
        service,
        admins: configuration.admins,
        secureCookies: true,
        dashboardDirectory: path.join(__dirname, "..", "admin-dashboard")
      });
      lastStartupFailure = undefined;
      return { service, handler };
    })().catch(error => {
      lastStartupFailure = getSafeFailure(
        error,
        stage
      );
      handlerPromise = undefined;
      throw error;
    });
  }
  return handlerPromise;
}

module.exports = async function licenseServerFunction(request, response) {
  try {
    if (request.method === "GET") {
      try {
        const healthUrl = new URL(request.url, `https://${request.headers.host || "localhost"}`);
        if ([TEMPORARY_SIGNING_KEY_DIAGNOSTIC_PATH,
          TEMPORARY_SIGNING_KEY_DIAGNOSTIC_PATH.replace(/^\/api/, "")]
          .includes(healthUrl.pathname)) {
          return handleSigningKeyFormatDiagnostic(request, response);
        }
        if (healthUrl.pathname === "/api/health") {
          if (healthUrl.searchParams.get("diagnostic") === "signing-key") {
            return handleSigningKeyFormatDiagnostic(request, response, true);
          }
          return await handleHealthCheck(response);
        }
      } catch {
        // Preserve the existing request error path for malformed URLs below.
      }
    }

    const { handler } = await getHandler();
    const requestUrl = new URL(request.url, `https://${request.headers.host || "localhost"}`);
    if (requestUrl.pathname === "/api") requestUrl.pathname = "/";
    else if (requestUrl.pathname.startsWith("/api/")) requestUrl.pathname = requestUrl.pathname.slice(4);
    request.url = `${requestUrl.pathname}${requestUrl.search}`;
    await handler(request, response);
  } catch (error) {
    logFailure("ShopPOS license serverless request failed.", error);
    if (response.headersSent) return response.end();
    response.writeHead(503, {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8"
    });
    response.end(JSON.stringify({ error: "The license service is temporarily unavailable." }));
  }
};

module.exports.config = { api: { bodyParser: false } };
