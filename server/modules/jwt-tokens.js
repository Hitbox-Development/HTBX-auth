import db from "./db.js";

const SECRET = process.env.JWT_SECRET

export function storeToken(uuid, token, ttlSeconds = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const expires = now + ttlSeconds;

  db.run(
    "INSERT INTO tokens (uuid, token, issued_at, expires_at) VALUES (?, ?, ?, ?)",
    uuid, token, now, expires
  );
}

export function getToken(token) {
  return db.query("SELECT * FROM tokens WHERE token = ?").get(token);
}

export function getTokensByUUID(uuid) {
  return db.query("SELECT * FROM tokens WHERE uuid = ?").all(uuid);
}

export function revokeToken(token) {
  db.run("DELETE FROM tokens WHERE token = ?", token);
}

export function revokeAllTokens(uuid) {
  db.run("DELETE FROM tokens WHERE uuid = ?", uuid);
}

export function cleanExpiredTokens() {
  const now = Math.floor(Date.now() / 1000);
  db.run("DELETE FROM tokens WHERE expires_at < ?", now);
}

export function verifyToken(token) {
  try {
    const payload = jwt.verify(token, SECRET);
    const record = db.query("SELECT * FROM tokens WHERE token = ?").get(token);

    if (!record || record.uuid !== payload.uuid) return null;

    const now = Math.floor(Date.now() / 1000);
    if (record.expires_at < now) return null;

    return payload;
  } catch (err) {
    return null;
  }
}