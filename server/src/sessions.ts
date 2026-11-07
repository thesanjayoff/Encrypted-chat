import { randomBytes, createHash } from "node:crypto";
import { db } from "./db.js";

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export interface SessionInfo {
  accountId: string;
  deviceId: string;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Returns the bearer token to hand to the client. Only its hash is stored —
 * a stolen database dump cannot be replayed as a session token. */
export function createSession(accountId: string, deviceId: string): string {
  const token = randomBytes(32).toString("base64url");
  const now = Date.now();
  db.prepare(
    `INSERT INTO sessions (token_hash, account_id, device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
  ).run(hashToken(token), accountId, deviceId, now, now + SESSION_TTL_MS);
  return token;
}

export function resolveSession(token: string): SessionInfo | null {
  const row = db
    .prepare(`SELECT account_id, device_id, expires_at FROM sessions WHERE token_hash = ?`)
    .get(hashToken(token)) as { account_id: string; device_id: string; expires_at: number } | undefined;
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).run(hashToken(token));
    return null;
  }
  return { accountId: row.account_id, deviceId: row.device_id };
}

export function revokeSession(token: string): void {
  db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).run(hashToken(token));
}
