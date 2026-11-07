import { randomUUID, createHash } from "node:crypto";
import { db } from "./db.js";
import { getConnections } from "./deviceRegistry.js";

export const DEFAULT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
export const MIN_TTL_MS = 5 * 1000;

export interface OutgoingEnvelope {
  toAccountId: string;
  toDeviceId: string;
  fromAccountId: string | null; // null when sealed-sender
  fromDeviceId: string | null;
  envelopeType: string;
  ciphertext: Buffer;
  ttlMs?: number;
}

/** Cheap defense-in-depth against trivial replay flooding: reject an exact
 * duplicate ciphertext blob addressed to the same device within a short
 * window. This is *not* what makes replay safe — the Double Ratchet/Sender
 * Key chains already reject a reused message key — it just stops a lazy
 * flood of byte-identical envelopes from piling up in the queue. */
function isRecentDuplicate(toDeviceId: string, ciphertext: Buffer): boolean {
  const hash = createHash("sha256").update(toDeviceId).update(ciphertext).digest("hex");
  const now = Date.now();
  const existing = db.prepare(`SELECT 1 FROM recent_message_hashes WHERE hash = ?`).get(hash);
  if (existing) return true;
  db.prepare(`INSERT OR IGNORE INTO recent_message_hashes (hash, to_device_id, created_at) VALUES (?, ?, ?)`).run(hash, toDeviceId, now);
  return false;
}

export function enqueueMessage(envelope: OutgoingEnvelope): { id: string; duplicate: boolean } {
  if (isRecentDuplicate(envelope.toDeviceId, envelope.ciphertext)) {
    return { id: "", duplicate: true };
  }

  const id = randomUUID();
  const now = Date.now();
  const ttl = Math.max(envelope.ttlMs ?? DEFAULT_RETENTION_MS, MIN_TTL_MS);
  db.prepare(
    `INSERT INTO messages (id, to_account_id, to_device_id, from_account_id, from_device_id, envelope_type, ciphertext, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, envelope.toAccountId, envelope.toDeviceId, envelope.fromAccountId, envelope.fromDeviceId, envelope.envelopeType, envelope.ciphertext, now, now + ttl);

  pushIfOnline(envelope.toDeviceId, {
    type: "message",
    message: serializeRow({
      id,
      to_account_id: envelope.toAccountId,
      to_device_id: envelope.toDeviceId,
      from_account_id: envelope.fromAccountId,
      from_device_id: envelope.fromDeviceId,
      envelope_type: envelope.envelopeType,
      ciphertext: envelope.ciphertext,
      created_at: now,
      expires_at: now + ttl,
    }),
  });

  return { id, duplicate: false };
}

export interface MessageRow {
  id: string;
  to_account_id: string;
  to_device_id: string;
  from_account_id: string | null;
  from_device_id: string | null;
  envelope_type: string;
  ciphertext: Buffer;
  created_at: number;
  expires_at: number;
}

export function serializeRow(row: MessageRow) {
  return {
    id: row.id,
    fromAccountId: row.from_account_id,
    fromDeviceId: row.from_device_id,
    envelopeType: row.envelope_type,
    ciphertext: row.ciphertext.toString("base64"),
    createdAt: row.created_at,
  };
}

export function pushIfOnline(deviceId: string, payload: unknown): void {
  const sockets = getConnections(deviceId);
  const data = JSON.stringify(payload);
  for (const socket of sockets) {
    try {
      socket.send(data);
    } catch {
      /* best-effort push; the DB queue remains authoritative */
    }
  }
}
