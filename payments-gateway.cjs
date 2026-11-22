// ShopPOS payment gateway abstraction layer.
//
// Provider-independent webhook verification and event normalization.
// No live payment provider is implemented here: enabling a real provider
// requires the project owner's approval and that provider's official
// developer documentation. A clearly-labelled homologous "test" adapter is
// included so the full webhook pipeline can be exercised in tests without
// inventing any third-party API behavior.
//
// Security summary:
// - Webhook secrets live only on the server (environment variables).
// - Signature verification uses the provider adapter's own verification
//   method over the RAW request body bytes, never a parsed re-serialization.
// - Every accepted delivery is stored in gateway_events keyed by (provider,
//   eventId) so repeat deliveries are idempotent.
// - Adapter errors never echo secret values.

"use strict";

const crypto = require("node:crypto");

const TEST_ADAPTER_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

// Standard normalized webhook event shape accepted by the license service.
// Every provider adapter must return this shape after verifying its own webhook.
//
// @typedef {Object} NormalizedGatewayEvent
// @property {string} eventId - Provider-unique event identifier
// @property {string} eventType - Provider event type string
// @property {string} transactionId - Provider transaction identifier
// @property {number} amountMinor - Amount in minor currency units
// @property {string} currency - ISO 4217 currency code (uppercase, 3 letters)
// @property {string} status - "succeeded" | "failed" | "refunded" | ...
// @property {string|null} customerReference - Original payment reference (for matching)
// @property {string|null} merchantReference - Provider merchant reference
// @property {Object|null} rawPayload - Original parsed provider payload (no secrets)

// Interface every provider adapter must implement.
//
// @interface GatewayAdapter
// @property {string} id - Provider identifier (lowercase, URL-safe)
// @property {boolean} sandboxOnly - True if adapter is sandbox/test only
// @property {function(): string} describe - Human-readable adapter description
// @property {function(): string|null} webhookConfigError - Returns config error or null if ready
// @property {boolean} canEnableInProduction - True if adapter is production-safe
// @property {function({rawBody: Buffer, headers: Object, env?: Object, now?: function}): NormalizedGatewayEvent} verifyWebhook - Verify raw body and return normalized event

// Homologous test adapter (SANDBOX ONLY). Verifies HMAC-SHA256 over the raw
// body with a per-installation secret, mirroring the common requirement that
// webhooks carry an authentic, secret-keyed signature. Do not enable outside
// controlled test environments.
const testAdapter = {
  id: "test",
  sandboxOnly: true,
  describe() {
    return "Sandbox test adapter: webhook HMAC-SHA256 (header 'x-shoppos-test-signature'), body JSON with eventId, transactionId, amountMinor, currency, status.";
  },
  webhookConfigError() {
    if (!process.env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET) {
      return "The gateway requires configuration before webhooks can be received.";
    }
    return null;
  },
  canEnableInProduction() {
    return false;
  },
  verifyWebhook({ rawBody, headers, env = process.env, now = () => Date.now() }) {
    const secret = env.PAYMENT_GATEWAY_TEST_WEBHOOK_SECRET;
    if (typeof secret !== "string" || secret.length < 32) {
      throw WebhookVerificationError("The test gateway webhook secret is missing or too short.");
    }
    const supplied = headers["x-shoppos-test-signature"];
    const timestamp = headers["x-shoppos-test-timestamp"];
    if (typeof supplied !== "string" || typeof timestamp !== "string") {
      throw WebhookVerificationError("The webhook signature or timestamp header is missing.");
    }
    const skewMs = typeof now === "function" ? now() - Number(timestamp) : 0;
    if (!Number.isFinite(skewMs) || Math.abs(skewMs) > TEST_ADAPTER_MAX_CLOCK_SKEW_MS) {
      throw WebhookVerificationError("The webhook timestamp is outside the allowed window.");
    }
    const expected = crypto.createHmac("sha256", secret)
      .update(Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), rawBody]))
      .digest("hex");
    const suppliedBuffer = Buffer.from(supplied.toLowerCase(), "utf8");
    const expectedBuffer = Buffer.from(expected, "utf8");
    if (suppliedBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) {
      throw WebhookVerificationError("The webhook signature is invalid.");
    }
    let payload;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch {
      throw WebhookVerificationError("The webhook body is not valid JSON.");
    }
    const eventId = payload.eventId;
    const eventType = payload.eventType;
    if (typeof eventId !== "string" || eventId.length < 1 || eventId.length > 120) {
      throw WebhookVerificationError("The webhook event id is missing or invalid.");
    }
    if (typeof eventType !== "string") {
      throw WebhookVerificationError("The webhook event type is missing or invalid.");
    }
    // Normalize to the server's standard payment event shape.
    const amountMinor = payload.amountMinor;
    if (!Number.isSafeInteger(amountMinor) || amountMinor < 0) {
      throw WebhookVerificationError("The webhook amount is missing or invalid.");
    }
    if (typeof payload.currency !== "string" || !/^[A-Za-z]{3}$/.test(payload.currency)) {
      throw WebhookVerificationError("The webhook currency is missing or invalid.");
    }
    if (typeof payload.transactionId !== "string" || payload.transactionId.length < 1 || payload.transactionId.length > 120) {
      throw WebhookVerificationError("The webhook transaction id is missing or invalid.");
    }
    return {
      eventId,
      eventType,
      transactionId: payload.transactionId,
      amountMinor,
      currency: payload.currency.toUpperCase(),
      merchantReference: typeof payload.merchantReference === "string" ? payload.merchantReference.slice(0, 200) : undefined,
      customerReference: typeof payload.customerReference === "string" ? payload.customerReference.slice(0, 200) : undefined,
      status: payload.status,
      rawPayload: payload
    };
  }
};

// Provider adapter registry. Only adapters registered here can receive
// webhook events. Each provider must be explicitly registered by the project
// owner after reviewing that provider's security documentation.
const ADAPTERS = new Map([["test", testAdapter]]);

/**
 * Return the registered gateway adapter for a provider ID, or undefined.
 * @param {string} providerId - Provider identifier
 * @returns {GatewayAdapter|undefined}
 */
function getGatewayAdapter(providerId) {
  return ADAPTERS.get(String(providerId ?? "").trim().toLowerCase());
}

/**
 * List all registered provider adapter IDs.
 * @returns {string[]}
 */
function listGatewayAdapters() {
  return [...ADAPTERS.keys()];
}

/**
 * Create a WebhookVerificationError with a name property for instanceof checks.
 * @param {string} message
 * @returns {Error}
 */
function WebhookVerificationError(message) {
  return Object.assign(new Error(message), { name: "WebhookVerificationError" });
}

module.exports = { getGatewayAdapter, listGatewayAdapters, WebhookVerificationError };
