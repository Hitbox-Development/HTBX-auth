import db from './db.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import logger from './logger.js';
import {  } from './crypto.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const TTL = process.env.TTL ? parseInt(process.env.TTL, 10) : 3600;

export default function handleMessage(message) {
  let type;
  let msg;
  try {
    msg = JSON.parse(message);
    type = msg.type;
  } catch (err) {
    logger.error(`Invalid JSON format: ${err?.message || err}`);
    return JSON.stringify({ type: 'error', message: 'Invalid JSON format' })
  }
  const { username, password, uuid } = msg;

  if (!username || !password || !uuid) {
    logger.error('Missing username, password, or uuid');
    return JSON.stringify({ type: 'error', message: 'Missing username, password, or uuid' })
  }

  if (type === 'register') {
    const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (existing) {
      logger.error(`Username already exists: ${username}`);
      return JSON.stringify({ type: 'error', message: 'Username already exists' })
    }

    const hashed = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashed);

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    db.prepare('INSERT INTO tokens (uuid, username, token) VALUES (?, ?, ?)').run(uuid, username, token);
    return JSON.stringify({ type: 'success', message: 'User registered', token })
  }

  if (type === 'login') {
    logger.info(`Login attempt for username: ${username}`);
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
      logger.error(`Invalid credentials for username: ${username}`);
      return JSON.stringify({ type: 'error', message: 'Invalid credentials' })
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: TTL });
    db.prepare('INSERT INTO tokens (uuid, token, issued_at, expires_at) VALUES (?, ?, ?, ?)').run(
      uuid,
      token,
      Date.now(),
      Date.now() + TTL
    );
    return JSON.stringify({ type: 'success', message: 'Login successful', token });
  }

  logger.error(`Unknown message type: ${type}`);
  return JSON.stringify({ type: 'error', message: 'Unknown message type' })
}
