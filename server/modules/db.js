import Database from "better-sqlite3";
const db = new Database("users.db", { create: true });

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );

  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT,
    token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

export default db;
