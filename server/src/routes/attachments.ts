import { Router } from "express";
import express from "express";
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { db } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { apiLimiter } from "../middleware/rateLimit.js";
import { ATTACHMENTS_DIR } from "../env.js";
import { DEFAULT_RETENTION_MS } from "../deliver.js";

export const attachmentsRouter = Router();

const MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024; // 50 MB ciphertext

/**
 * The body here is already client-side-encrypted ciphertext (random key per
 * file, generated on-device; the key travels inside the E2E-encrypted
 * message, never touches this endpoint). The server can validate size and
 * that it's *some* binary blob — it cannot and does not inspect content.
 */
attachmentsRouter.post(
  "/",
  requireAuth,
  apiLimiter,
  express.raw({ type: "application/octet-stream", limit: MAX_ATTACHMENT_BYTES }),
  (req, res) => {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      res.status(400).json({ error: "empty or invalid body" });
      return;
    }
    const id = randomUUID();
    const filePath = path.join(ATTACHMENTS_DIR, `${id}.bin`);
    fs.writeFileSync(filePath, req.body);

    const now = Date.now();
    db.prepare(`INSERT INTO attachments (id, owner_account_id, size_bytes, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`).run(
      id,
      req.session!.accountId,
      req.body.length,
      now,
      now + DEFAULT_RETENTION_MS,
    );

    res.status(201).json({ id, size: req.body.length });
  },
);

attachmentsRouter.get("/:id", requireAuth, apiLimiter, (req, res) => {
  const row = db.prepare(`SELECT id, expires_at FROM attachments WHERE id = ?`).get(req.params.id) as
    | { id: string; expires_at: number }
    | undefined;
  if (!row || row.expires_at < Date.now()) {
    res.status(404).json({ error: "not found or expired" });
    return;
  }
  const filePath = path.join(ATTACHMENTS_DIR, `${row.id}.bin`);
  if (!fs.existsSync(filePath)) {
    res.status(404).json({ error: "not found" });
    return;
  }
  res.setHeader("content-type", "application/octet-stream");
  fs.createReadStream(filePath).pipe(res);
});
