import * as crypto from "node:crypto";

export function generateEphemeralKeyPair() {
  return crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

export function deriveSharedSecret(privateKeyPem, peerPublicKeyPem) {
  const privateKey = crypto.createPrivateKey({
    key: privateKeyPem,
    format: "pem",
  });
  const peerPublicKey = crypto.createPublicKey({
    key: peerPublicKeyPem,
    format: "pem",
  });
  const rawSecret = crypto.diffieHellman({ privateKey, publicKey: peerPublicKey });
  return crypto.diffieHellman({ privateKey, publicKey: peerPublicKey });
}

export function encryptMessage(sharedSecret, plaintext) {
  if (!Buffer.isBuffer(sharedSecret)) {
    sharedSecret = Buffer.from(sharedSecret);
  }
  if (sharedSecret.length !== 32) {
    throw new Error(`Invalid sharedSecret length: got ${sharedSecret.length}, expected 32`);
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", sharedSecret, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    payload: encrypted.toString("hex"),
    tag: authTag.toString("hex"),
  };
}


/**
 * Decrypts AES-GCM-encrypted data.
 * @param {Object} param0 - Encrypted payload
 * @param {string} param0.iv - Initialization vector as hex string
 * @param {string} param0.payload - Ciphertext + auth tag as hex string
 * @param {Buffer} sharedSecret - AES key as Buffer (32 bytes)
 */
export function decryptMessage(sharedSecret, { iv, payload, tag }) {
  if (!iv || !payload || !tag) {
    throw new Error("Missing IV, payload, or auth tag");
  }
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    sharedSecret,
    Buffer.from(iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(tag, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload, "hex")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
