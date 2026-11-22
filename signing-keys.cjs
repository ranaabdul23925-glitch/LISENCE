"use strict";

const crypto = require("node:crypto");

function normalizePublicKeys(keys) {
  const normalized = [];
  const fingerprints = new Set();
  for (const value of keys) {
    let key;
    try {
      if (value?.type === "public") {
        key = value;
      } else {
        if (typeof value !== "string" || !value.includes("-----BEGIN PUBLIC KEY-----")) {
          throw new Error();
        }
        key = crypto.createPublicKey(value);
      }
    } catch {
      throw new Error("Trusted license verification keys must be valid Ed25519 public keys.");
    }
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error("Trusted license verification keys must be Ed25519 public keys.");
    }
    const fingerprint = crypto.createHash("sha256")
      .update(key.export({ type: "spki", format: "der" }))
      .digest("hex");
    if (!fingerprints.has(fingerprint)) {
      if (normalized.length >= 9) {
        throw new Error("At most nine trusted license verification keys are supported.");
      }
      fingerprints.add(fingerprint);
      normalized.push(key);
    }
  }
  return normalized;
}

function parseTrustedPublicKeys(raw, activePublicKey) {
  let configured = [];
  if (raw !== undefined && raw !== "") {
    try {
      configured = JSON.parse(raw);
    } catch {
      throw new Error("LICENSE_TRUSTED_PUBLIC_KEYS_JSON must contain a JSON array of PEM public keys.");
    }
    if (!Array.isArray(configured) || configured.length > 8 ||
        configured.some(key => typeof key !== "string" || !key.trim())) {
      throw new Error("LICENSE_TRUSTED_PUBLIC_KEYS_JSON must contain a JSON array of PEM public keys.");
    }
  }
  return normalizePublicKeys([activePublicKey, ...configured.map(key => key.replace(/\\n/g, "\n"))]);
}

function verifyWithTrustedPublicKeys(data, signature, publicKeys) {
  for (const publicKey of publicKeys) {
    if (crypto.verify(null, data, publicKey, signature)) return true;
  }
  return false;
}

module.exports = {
  normalizePublicKeys,
  parseTrustedPublicKeys,
  verifyWithTrustedPublicKeys
};
