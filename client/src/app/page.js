"use client";
import { useEffect, useRef, useState } from "react";

const uuid = typeof window !== "undefined" ? window.crypto.randomUUID() : "";

export default function LoginPage() {
  const wsRef = useRef(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [logs, setLogs] = useState([]);
  const [connected, setConnected] = useState(false);
  const [loginUser, setLoginUser] = useState("");

  function log(msg) {
    setLogs((prev) => [...prev, msg]);
  }

  async function fetchWsUrl() {
    try {
      const res = await fetch(`http://localhost:3001/login/init?uuid=${uuid}`);
      const data = await res.json();
      if (!data.wsUrl) throw new Error("No wsUrl in response");
      return data.wsUrl;
    } catch (err) {
      log(`❗ Failed to get wsUrl: ${err.message}`);
      throw err;
    }
  }

  useEffect(() => {
    let clientKeys, sharedSecret;

    async function generateEphemeralKey() {
      return await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
    }

    async function exportPublicKey(key) {
      const raw = await window.crypto.subtle.exportKey("spki", key);
      const b64 = btoa(String.fromCharCode(...new Uint8Array(raw)));

      const pem = `-----BEGIN PUBLIC KEY-----\n${b64
        .match(/.{1,64}/g)
        .join("\n")}\n-----END PUBLIC KEY-----`;
      return pem;
    }

    async function importServerKey(base64) {
      const raw = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
      return await crypto.subtle.importKey(
        "spki",
        raw,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
    }

    async function deriveSharedSecret(privKey, pubKey) {
      const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: pubKey },
        privKey,
        256
      );

      return await crypto.subtle.importKey(
        "raw",
        sharedBits,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
    }

    async function connectWebSocket() {
      try {
        const wsUrl = await fetchWsUrl();
        clientKeys = await generateEphemeralKey();
        const clientPub = await exportPublicKey(clientKeys.publicKey);

        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          log("🔌 Securely Connecting To Server...");
          setConnected(true);
          ws.send(
            JSON.stringify({ type: "client-public-key", key: clientPub })
          );
        };

        ws.onmessage = async (event) => {
          try {
            const data = JSON.parse(event.data);

            if (data.type === "server-public-key") {
              if (typeof data.serverPubKey !== "string") {
                return;
              }
              const serverKey = await importServerKey(data.serverPubKey);
              sharedSecret = await deriveSharedSecret(
                clientKeys.privateKey,
                serverKey
              );
              wsRef.current.sharedSecret = sharedSecret;
              log("🔑 End-To-End Encryption Works!");
            } else if (data.payload && data.iv && data.tag) {
              const decryptedRaw = await decrypt(
                data,
                wsRef.current.sharedSecret
              );
              const decrypted = JSON.parse(decryptedRaw);

              log("Decrypted message: " + JSON.stringify(decrypted));

              if (decrypted.type === "success") {
                setLoginUser(decrypted.username || username);
                log(`✅ Login successful: ${decrypted.message}`);
              }
            } else if (data.type === "error") {
              log(`❗ Error: ${data.message}`);
              ws.close();
            }
          } catch (err) {
            console.error("❗ Failed to handle message (full error):", err);
            log(
              "❗ Failed to handle message (stringified): " +
                JSON.stringify(err)
            );
            log(
              "❗ Failed to handle message (stack): " +
                (err?.stack ?? "No stack")
            );
          }
        };

        ws.onerror = (err) => log("🚨 Server error");
        ws.onclose = () => {
          log("❌ Server - Login Portal closed, Please refresh and try again.");
          setConnected(false);
        };
      } catch (err) {
        log(`❗ End-To-End Encryption setup failed: ${err}`);
      }
    }

    connectWebSocket();
  }, []);

  async function encrypt(plain, key) {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = enc.encode(plain);

    const ciphertextWithTag = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded)
    );

    const tagLength = 16;
    const ciphertext = ciphertextWithTag.slice(0, -tagLength);
    const tag = ciphertextWithTag.slice(-tagLength);

    return {
      iv: Buffer.from(iv).toString("hex"),
      payload: Buffer.from(ciphertext).toString("hex"),
      tag: Buffer.from(tag).toString("hex"),
    };
  }

  async function decrypt({ iv, payload, tag }, key) {
    const ivBytes = Uint8Array.from(Buffer.from(iv, "hex"));
    const payloadBytes = Uint8Array.from(Buffer.from(payload, "hex"));
    const tagBytes = Uint8Array.from(Buffer.from(tag, "hex"));

    const fullCiphertext = new Uint8Array(
      payloadBytes.length + tagBytes.length
    );
    fullCiphertext.set(payloadBytes);
    fullCiphertext.set(tagBytes, payloadBytes.length);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      key,
      fullCiphertext
    );

    return new TextDecoder().decode(decrypted);
  }

  async function submitLogin() {
    if (!wsRef.current?.sharedSecret) {
      log("🔒 Shared secret not ready");
      return;
    }

    const creds = JSON.stringify({ type: "login", username, password, uuid });
    const encrypted = await encrypt(creds, wsRef.current.sharedSecret);
    wsRef.current.send(JSON.stringify(encrypted));
    log("📤 Attempting login...");
  }

  return (
    <div style={{ padding: 20 }}>
      <h1>🔐 Secure Login</h1>
      <input
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <br />
      <input
        placeholder="Password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <br />
      <button onClick={submitLogin} disabled={!connected}>
        Login
      </button>
      {loginUser && (
        <p style={{ color: "green", fontWeight: "bold", marginTop: 10 }}>
          ✅ Logged in successfully as <span>{loginUser}</span>
        </p>
      )}
      <pre>
        {logs.map((log, i) => (
          <div key={i}>{log}</div>
        ))}
      </pre>
    </div>
  );
}
