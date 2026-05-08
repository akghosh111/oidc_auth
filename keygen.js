const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// Directory where keys will be stored
const CERT_DIR = "cert";

// Create directory if it doesn't exist
if (!fs.existsSync(CERT_DIR)) {
  fs.mkdirSync(CERT_DIR, { recursive: true });
}

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,

  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },

  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

// Save keys
fs.writeFileSync(
  path.join(CERT_DIR, "private-key.pem"),
  privateKey
);

fs.writeFileSync(
  path.join(CERT_DIR, "public-key.pub"),
  publicKey
);

console.log(`Keys have been generated in the ${CERT_DIR}/ folder.`);