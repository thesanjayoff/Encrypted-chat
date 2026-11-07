import fs from "node:fs";
import path from "node:path";
import { db } from "./db.js";
import { ATTACHMENTS_DIR } from "./env.js";

/** Deletes anything past its expiry: queued ciphertext, attachments,
 * expired sessions and link tokens, and the short-lived replay-dedupe
 * cache. Nothing in this module ever reads message content. */
export function sweepExpired(): void {
  const now = Date.now();

  db.prepare(`DELETE FROM messages WHERE expires_at < ?`).run(now);
  db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).run(now);
  db.prepare(`DELETE FROM device_link_sessions WHERE expires_at < ?`).run(now);
  db.prepare(`DELETE FROM pending_logins WHERE created_at < ?`).run(now - 10 * 60 * 1000);
  db.prepare(`DELETE FROM recent_message_hashes WHERE created_at < ?`).run(now - 10 * 60 * 1000);

  const expiredAttachments = db.prepare(`SELECT id FROM attachments WHERE expires_at < ?`).all(now) as { id: string }[];
  for (const a of expiredAttachments) {
    const filePath = path.join(ATTACHMENTS_DIR, `${a.id}.bin`);
    fs.rm(filePath, { force: true }, () => {});
  }
  if (expiredAttachments.length) {
    db.prepare(`DELETE FROM attachments WHERE expires_at < ?`).run(now);
  }
}

export function startRetentionSweeper(intervalMs = 60 * 1000): NodeJS.Timeout {
  return setInterval(sweepExpired, intervalMs);
}
