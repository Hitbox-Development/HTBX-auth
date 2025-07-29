import { createSession, attachSocket } from "../modules/ws-sessions.js";
import logger from "../modules/logger.js";
import * as crypto from "node:crypto";
import handleMessage from "../modules/auth.js";
import {
  generateEphemeralKeyPair,
  deriveSharedSecret,
  decryptMessage,
  encryptMessage,
} from "../modules/crypto.js";

export function init(req, res) {
  const uuid = req.query.uuid;
  if (!uuid) return res.status(400).json({ error: "UUID required" });

  const token = createSession(uuid);
  const wsUrl = `ws://${req.headers.host}/login?uuid=${uuid}&token=${token}`;
  logger.info(`Login session created for UUID ${uuid}`);

  res.json({ wsUrl });
}

export function wsHandler(ws, req) {
  let hasSharedSecret = false;
  let sharedSecret, ephemeralPrivateKey;

  const timeout = setTimeout(() => {
    if (!hasSharedSecret) {
      ws.send(
        JSON.stringify({ error: "Timeout: No client-public-key received" })
      );
      logger.info("Closing websocket: client-public-key timeout");
      ws.close();
    }
  }, 3000);

  ws.send(JSON.stringify({ status: "awaiting-client-public-key" }));

  ws.on("message", (msg) => {
    let parsed;
    try {
      parsed = JSON.parse(msg.toString());
    } catch {
      ws.send(JSON.stringify({ error: "Invalid JSON" }));
      logger.info("Closing websocket: invalid JSON in login");
      return ws.close();
    }

    if (!hasSharedSecret && parsed.type === "client-public-key" && parsed.key) {
      clearTimeout(timeout);
      try {
        const { publicKey, privateKey } = generateEphemeralKeyPair();
        sharedSecret = deriveSharedSecret(privateKey, parsed.key);
        ephemeralPrivateKey = privateKey;
        hasSharedSecret = true;
        ws.sharedSecret = sharedSecret;
        ws.ephemeralPrivateKey = privateKey;
        const serverRawPubKey = crypto
          .createPublicKey(publicKey)
          .export({ type: "spki", format: "der" });
        const serverPubKeyB64 = serverRawPubKey.toString("base64");
        ws.send(
          JSON.stringify({
            type: "server-public-key",
            serverPubKey: serverPubKeyB64,
          })
        );
        logger.info("✅ Shared secret established with client");
      } catch (err) {
        console.error("[Key exchange error]", err);
        ws.send(JSON.stringify({ error: "Key exchange failed" }));
        logger.info("Closing websocket: key exchange failed");
        ws.close();
      }
    } else if (hasSharedSecret) {
      const { iv, payload, tag } = parsed;
      if (
        typeof iv !== "string" ||
        typeof payload !== "string" ||
        typeof tag !== "string"
      ) {
        ws.send(JSON.stringify({ error: "Invalid iv/payload/tag format" }));
        return ws.close();
      }

      try {
        const decrypted = decryptMessage(sharedSecret, { iv, payload, tag });

        const response = handleMessage(decrypted);
        const encrypted = encryptMessage(sharedSecret, response);

        ws.send(JSON.stringify(encrypted));
        logger.info("✅ Auth message processed and sent back");
        ws.close();
      } catch (err) {
        console.error("[Decrypt/Auth Error]", err);
        ws.send(
          JSON.stringify({ error: "Auth failed or bad encrypted message" })
        );
        ws.close();
      }
    } else if (!hasSharedSecret) {
      const expectedKeyMsg = JSON.stringify({
        error: "Expected client-public-key first",
      });
      logger.info(`[WS] Sending: ${expectedKeyMsg}`);
      ws.send(expectedKeyMsg);
      logger.info("Closing websocket: expected client-public-key first");
      ws.close();
    }
  });
}
