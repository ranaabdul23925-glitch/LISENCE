const crypto = require("node:crypto");

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" }
});

console.log("LICENSE_SIGNING_PRIVATE_KEY (server secret):");
console.log(privateKey);
console.log("SHOPPOS_LICENSE_PUBLIC_KEY (desktop verification key; not secret):");
console.log(publicKey);
