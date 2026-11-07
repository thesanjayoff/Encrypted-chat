import { Router } from "express";
import { randomUUID, randomBytes } from "node:crypto";
import { z } from "zod";
import { verifySignedPreKey } from "@e2e-chat/crypto";
import { db } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { authLimiter } from "../middleware/rateLimit.js";
import { createSession } from "../sessions.js";

export const devicesRouter = Router();

const LINK_TTL_MS = 5 * 60 * 1000;

function b64ToBuffer(s: string): Buffer {
  return Buffer.from(s, "base64");
}

devicesRouter.get("/", requireAuth, (req, res) => {
  const rows = db
    .prepare(`SELECT id, label, is_primary, created_at, last_seen_at FROM devices WHERE account_id = ?`)
    .all(req.session!.accountId);
  res.json({ devices: rows });
});

/**
 * Step 1 of device linking: the already-logged-in (primary) device asks for
 * a one-time link token, which it renders as a QR code. This token only
 * lets a new device open an end-to-end encrypted relay channel with THIS
 * device (see ws/linkRelay.ts) — the server never sees what passes through
 * that channel (the two devices run their own X25519 handshake over it),
 * only that it granted the token holder permission to register one new
 * device for this account.
 */
devicesRouter.post("/link/start", requireAuth, authLimiter, (req, res) => {
  const token = randomBytes(24).toString("base64url");
  const now = Date.now();
  db.prepare(
    `INSERT INTO device_link_sessions (token, primary_account_id, primary_device_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)`,
  ).run(token, req.session!.accountId, req.session!.deviceId, now, now + LINK_TTL_MS);
  res.status(201).json({ linkToken: token, expiresAt: now + LINK_TTL_MS });
});

const registerSchema = z.object({
  linkToken: z.string().min(1),
  identitySigningPublicKey: z.string(),
  identityDhKey: z.string(),
  device: z.object({
    label: z.string().max(64).optional(),
    signedPreKeyId: z.number().int().nonnegative(),
    signedPreKeyPublic: z.string(),
    signedPreKeySignature: z.string(),
    oneTimePreKeys: z.array(z.object({ keyId: z.number().int().nonnegative(), publicKey: z.string() })).min(1).max(200),
  }),
});

/**
 * Step 2: the new device, having received the account's identity key pair
 * over the end-to-end relay channel (so it can sign/decrypt as that same
 * identity — this is what makes it a trusted additional device under the
 * existing safety-number verification, exactly like a real Signal-linked
 * device), presents the link token to actually register itself. No OPAQUE
 * login happens here — trust comes from the out-of-band QR scan plus
 * holding the account's real identity key material, not a password.
 */
devicesRouter.post("/link/register", authLimiter, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const { linkToken, identitySigningPublicKey, identityDhKey, device } = parsed.data;

  const link = db.prepare(`SELECT * FROM device_link_sessions WHERE token = ?`).get(linkToken) as
    | { token: string; primary_account_id: string; expires_at: number; used: number }
    | undefined;
  if (!link || link.used || link.expires_at < Date.now()) {
    res.status(401).json({ error: "invalid or expired link token" });
    return;
  }

  const accountRow = db.prepare(`SELECT identity_signing_public_key, identity_dh_public_key FROM accounts WHERE id = ?`).get(link.primary_account_id) as
    | { identity_signing_public_key: Buffer; identity_dh_public_key: Buffer }
    | undefined;
  if (!accountRow) {
    res.status(404).json({ error: "account not found" });
    return;
  }

  // The new device must present the SAME identity keys as the account it's
  // linking to (proof it really received them over the authenticated relay
  // channel, not just anyone calling this endpoint with the right token).
  if (
    !accountRow.identity_signing_public_key.equals(b64ToBuffer(identitySigningPublicKey)) ||
    !accountRow.identity_dh_public_key.equals(b64ToBuffer(identityDhKey))
  ) {
    res.status(403).json({ error: "identity key mismatch" });
    return;
  }

  const sigOk = verifySignedPreKey(
    b64ToBuffer(identitySigningPublicKey),
    b64ToBuffer(device.signedPreKeyPublic),
    b64ToBuffer(device.signedPreKeySignature),
  );
  if (!sigOk) {
    res.status(400).json({ error: "Signed PreKey signature does not verify" });
    return;
  }

  const deviceId = randomUUID();
  const now = Date.now();
  const tx = db.transaction(() => {
    db.prepare(`UPDATE device_link_sessions SET used = 1 WHERE token = ?`).run(linkToken);
    db.prepare(
      `INSERT INTO devices (id, account_id, label, is_primary, signed_prekey_id, signed_prekey_public, signed_prekey_signature, signed_prekey_created_at, created_at)
       VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?)`,
    ).run(deviceId, link.primary_account_id, device.label ?? null, device.signedPreKeyId, b64ToBuffer(device.signedPreKeyPublic), b64ToBuffer(device.signedPreKeySignature), now, now);
    const insertOtpk = db.prepare(`INSERT INTO one_time_prekeys (device_id, key_id, public_key, created_at) VALUES (?, ?, ?, ?)`);
    for (const otpk of device.oneTimePreKeys) insertOtpk.run(deviceId, otpk.keyId, b64ToBuffer(otpk.publicKey), now);
  });
  tx();

  const sessionToken = createSession(link.primary_account_id, deviceId);
  res.status(201).json({ accountId: link.primary_account_id, deviceId, sessionToken });
});

devicesRouter.delete("/:id", requireAuth, (req, res) => {
  if (req.params.id === req.session!.deviceId) {
    res.status(400).json({ error: "cannot remove your current device this way — log out instead" });
    return;
  }
  db.prepare(`DELETE FROM devices WHERE id = ? AND account_id = ?`).run(req.params.id, req.session!.accountId);
  res.status(204).end();
});
