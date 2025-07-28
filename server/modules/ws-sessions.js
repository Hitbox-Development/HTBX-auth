import bcrypt from 'bcrypt';
import * as crypto from 'node:crypto';
import logger from './logger.js';

// sessions: Map<sessionID, { hashedUUID: string, socket?: WebSocket }>
const sessions = new Map();

export function createSession(uuid) {
  const sessionID = crypto.randomUUID();
  const hashedUUID = bcrypt.hashSync(uuid, 10);
  sessions.set(sessionID, { hashedUUID });
  logger.info(`Session created with ID: ${sessionID} for UUID: ${uuid}`);
  return sessionID;
}

export function attachSocket(sessionID, socket, uuid) {
  if (sessions.has(sessionID)) {
    const session = sessions.get(sessionID);
    if (bcrypt.compareSync(uuid, session.hashedUUID)) {
      // If a socket is already attached, block new connection
      if (session.socket && session.socket.readyState === 1) {
        logger.warning(`❌ WebSocket already attached for session ID: ${sessionID}. Blocking new connection.`);
        return false;
      }
      session.socket = socket;
      socket.sessionID = sessionID;
      socket.uuid = uuid;
      logger.info(`✅ WebSocket attached with UUID: ${uuid}`);
      return true;
    }
    logger.error(`❌ UUID mismatch for session ID: ${sessionID}`);
    return false;
  }
  logger.error(`❌ Session ID not found: ${sessionID}`);
  return false;
}

export function getSocket(sessionID) {
  const session = sessions.get(sessionID);
  return session && session.socket ? session.socket : null;
}

export function removeSession(sessionID) {
  if (sessions.has(sessionID)) {
    const session = sessions.get(sessionID);
    if (session.socket && session.socket.readyState === 1) {
      session.socket.close(4001, 'Session removed');
    }
    sessions.delete(sessionID);
    logger.info(`🗑️ Session removed with ID: ${sessionID}`);
  } else {
    logger.error(`⚠️ Attempted to remove non-existent session ID: ${sessionID}`);
  }
}
