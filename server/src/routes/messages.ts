import { Router } from "express";
import { z } from "zod";
import { db } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { apiLimiter } from "../middleware/rateLimit.js";
import { enqueueMessage, serializeRow, DEFAULT_RETENTION_MS, type MessageRow } from "../deliver.js";

export const messagesRouter = Router();

const ENVELOPE_TYPES = ["prekey", "ratchet", "senderkey-distribution", "control"] as const;

const sendSchema = z.object({
  toDeviceId: z.string().uuid(),
  envelopeType: z.enum(ENVELOPE_TYPES),
  ciphertext: z.string().min(1),
  sealedSender: z.boolean().optional(),
  ttlSeconds: z.number().int().positive().max(DEFAULT_RETENTION_MS / 1000).optional(),
});

messagesRouter.post("/", requireAuth, apiLimiter, (req, res) => {
  const parsed = sendSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request", details: parsed.error.flatten() });
    return;
  }
  const { toDeviceId, envelopeType, ciphertext, sealedSender, ttlSeconds } = parsed.data;

  const device = db.prepare(`SELECT account_id FROM devices WHERE id = ?`).get(toDeviceId) as { account_id: string } | undefined;
  if (!device) {
    res.status(404).json({ error: "unknown recipient device" });
    return;
  }

  const { id, duplicate } = enqueueMessage({
    toAccountId: device.account_id,
    toDeviceId,
    fromAccountId: sealedSender ? null : req.session!.accountId,
    fromDeviceId: sealedSender ? null : req.session!.deviceId,
    envelopeType,
    ciphertext: Buffer.from(ciphertext, "base64"),
    ttlMs: ttlSeconds ? ttlSeconds * 1000 : undefined,
  });

  if (duplicate) {
    res.status(202).json({ id: null, duplicate: true });
    return;
  }
  res.status(201).json({ id });
});

/** Catch-up poll: a device calls this on connect/reconnect to get anything
 * it missed while offline. The WebSocket push is the fast path; this is the
 * durable fallback (the DB row isn't deleted until the device acks it). */
messagesRouter.get("/", requireAuth, apiLimiter, (req, res) => {
  const rows = db
    .prepare(`SELECT * FROM messages WHERE to_device_id = ? ORDER BY created_at ASC LIMIT 500`)
    .all(req.session!.deviceId) as MessageRow[];
  res.json({ messages: rows.map(serializeRow) });
});

const ackSchema = z.object({ messageIds: z.array(z.string().uuid()).min(1).max(500) });

messagesRouter.post("/ack", requireAuth, apiLimiter, (req, res) => {
  const parsed = ackSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const del = db.prepare(`DELETE FROM messages WHERE id = ? AND to_device_id = ?`);
  const tx = db.transaction((ids: string[]) => {
    let count = 0;
    for (const id of ids) count += del.run(id, req.session!.deviceId).changes;
    return count;
  });
  const deleted = tx(parsed.data.messageIds);
  res.json({ deleted });
});
