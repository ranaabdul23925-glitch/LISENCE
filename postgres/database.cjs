const crypto = require("node:crypto");
const { Pool } = require("pg");

const SSL_CONNECTION_PARAMETERS = new Set([
  "ssl",
  "sslmode",
  "sslcert",
  "sslkey",
  "sslrootcert",
  "uselibpqcompat",
  "sslnegotiation"
]);
const CERTIFICATE_ERROR_CODES = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "CERT_HAS_EXPIRED",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_GET_LOCAL_ISSUER_CERT",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_GET_CRL",
  "UNABLE_TO_DECRYPT_CERT_SIGNATURE"
]);

function getPostgresErrorDiagnostic(error) {
  const seen = new Set();
  const pending = [error];
  const errors = [];

  while (pending.length && errors.length < 16) {
    const current = pending.pop();
    if (!current || typeof current !== "object" || seen.has(current)) continue;
    seen.add(current);
    errors.push(current);

    if (current.cause && typeof current.cause === "object" &&
        pending.length + errors.length < 16) {
      pending.push(current.cause);
    }
    if (Array.isArray(current.errors)) {
      for (const nested of current.errors) {
        if (pending.length + errors.length >= 16) break;
        if (nested && typeof nested === "object") pending.push(nested);
      }
    }
  }

  const codes = errors.flatMap(current => [
    typeof current.code === "string" ? current.code.toUpperCase() : "",
    typeof current.name === "string" ? current.name.toUpperCase() : ""
  ]);
  const hasCode = pattern => codes.some(code => pattern.test(code));
  const certificateCode = codes.find(code => CERTIFICATE_ERROR_CODES.has(code));

  if (certificateCode) {
    return { category: "TLS_CERTIFICATE_ERROR", certificateCode };
  }
  if (hasCode(/^(?:ERR_TLS_|ERR_SSL_|EPROTO$)/)) {
    return { category: "TLS_HANDSHAKE_ERROR", certificateCode: null };
  }
  if (hasCode(/^(?:28P01|28000)$/)) return { category: "AUTH_ERROR", certificateCode: null };
  if (hasCode(/^ECONNREFUSED$/)) return { category: "ECONNREFUSED", certificateCode: null };
  if (hasCode(/^ENOTFOUND$/)) return { category: "ENOTFOUND", certificateCode: null };
  if (hasCode(/^(?:ETIMEDOUT|ESOCKETTIMEDOUT)$/)) return { category: "ETIMEDOUT", certificateCode: null };
  if (hasCode(/^(?:ECONNRESET|ECONNABORTED|EHOSTUNREACH|ENETUNREACH|EPIPE|EAI_AGAIN|EADDRNOTAVAIL)$/)) {
    return { category: "CONNECTION_ERROR", certificateCode: null };
  }

  return { category: "UNKNOWN", certificateCode: null };
}

function classifyPostgresError(error) {
  return getPostgresErrorDiagnostic(error).category;
}

function decodeCaCertificate(base64Certificate) {
  if (typeof base64Certificate !== "string" || !base64Certificate.trim()) {
    throw new Error("SHOPPOS_DATABASE_CA_CERT_BASE64 must contain a Base64-encoded PEM CA certificate.");
  }

  const encoded = base64Certificate.replace(/\s/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?|)$/.test(encoded)) {
    throw new Error("SHOPPOS_DATABASE_CA_CERT_BASE64 must contain valid Base64-encoded PEM data.");
  }

  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")) {
    throw new Error("SHOPPOS_DATABASE_CA_CERT_BASE64 must contain valid Base64-encoded PEM data.");
  }

  const pem = decoded.toString("utf8");
  const certificatePattern = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  const certificates = pem.match(certificatePattern);
  if (!certificates || pem.replace(certificatePattern, "").trim()) {
    throw new Error("SHOPPOS_DATABASE_CA_CERT_BASE64 must contain one or more valid PEM certificates.");
  }

  try {
    for (const certificate of certificates) {
      new crypto.X509Certificate(certificate);
    }
  } catch {
    throw new Error("SHOPPOS_DATABASE_CA_CERT_BASE64 must contain one or more valid PEM certificates.");
  }

  return pem;
}

function normalizeConnectionString(connectionString) {
  let url;
  try {
    url = new URL(connectionString);
  } catch {
    throw new Error("SHOPPOS_DATABASE_URL must be a valid PostgreSQL connection URL.");
  }
  if (!["postgres:", "postgresql:"].includes(url.protocol)) {
    throw new Error("SHOPPOS_DATABASE_URL must use the PostgreSQL protocol.");
  }

  for (const key of [...url.searchParams.keys()]) {
    if (SSL_CONNECTION_PARAMETERS.has(key.toLowerCase())) {
      url.searchParams.delete(key);
    }
  }
  return url.toString();
}

function createPoolConfig(connectionString, {
  caCertificateBase64 = process.env.SHOPPOS_DATABASE_CA_CERT_BASE64,
  production = process.env.NODE_ENV === "production"
} = {}) {
  if (!connectionString) {
    throw new Error("SHOPPOS_DATABASE_URL is missing.");
  }
  if (production && !caCertificateBase64) {
    throw new Error("SHOPPOS_DATABASE_CA_CERT_BASE64 is required in production for verified Supabase TLS.");
  }

  const ca = caCertificateBase64 ? decodeCaCertificate(caCertificateBase64) : undefined;
  return {
    connectionString: normalizeConnectionString(connectionString),
    ssl: ca ? { ca, rejectUnauthorized: true } : { rejectUnauthorized: true },
    max: 2,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 15000,
    statement_timeout: 15000
  };
}

function createDatabase(connectionString = process.env.SHOPPOS_DATABASE_URL) {
  const pool = new Pool(createPoolConfig(connectionString));

  pool.on("error", (error) => {
    console.error("Unexpected PostgreSQL pool error.", {
      ...getPostgresErrorDiagnostic(error)
    });
  });

  return {
    async query(text, values = []) {
      return pool.query(text, values);
    },

    async transaction(callback) {
      const client = await pool.connect();

      try {
        await client.query("BEGIN");
        const result = await callback(client);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        try {
          await client.query("ROLLBACK");
        } catch (rollbackError) {
          error.rollbackError = rollbackError;
        }
        throw error;
      } finally {
        client.release();
      }
    },

    async healthCheck() {
      const result = await pool.query(
        "SELECT current_database() AS database, NOW() AS server_time"
      );

      return { connected: true, serverTime: result.rows[0].server_time };
    },

    async close() {
      await pool.end();
    },
  };
}

module.exports = {
  classifyPostgresError,
  createDatabase,
  createPoolConfig,
  decodeCaCertificate,
  getPostgresErrorDiagnostic,
  normalizeConnectionString
};