import { Router } from "express";
import { z } from "zod";
import { verifySignedPreKey } from "@e2e-chat/crypto";
import { db } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { prekeyFetchLimiter } from "../middleware/rateLimit.js";

export const keysRouter = Router();

function b64ToBuffer(s: string): Buffer {
  return Buffer.from(s, "base64");
}

interface DeviceRow {
  id: string;
  signed_prekey_id: number;
  signed_prekey_public: Buffer;
  signed_prekey_signature: Buffer;
}

/** One bundle per device of the target account (multi-device X3DH fanout):
 * the caller establishes a separate session with each device. Each fetch
 * atomically consumes (deletes) one one-time prekey per device so it can
 * never be handed out twice. */
keysRouter.get("/bundles/:username", requireAuth, prekeyFetchLimiter, (req, res) => {
  const { username } = req.params;
  const account = db.prepare(`SELECT id, identity_signing_public_key, identity_dh_public_key FROM accounts WHERE username = ?`).get(username) as
    | { id: string; identity_signing_public_key: Buffer; identity_dh_public_key: Buffer }
    | undefined;
  if (!account) {
    res.status(404).json({ error: "no such user" });
    return;
  }

  const devices = db
    .prepare(`SELECT id, signed_prekey_id, signed_prekey_public, signed_prekey_signature FROM devices WHERE account_id = ?`)
    .all(account.id) as DeviceRow[];

  if (devices.length === 0) {
    res.status(404).json({ error: "user has no registered devices" });
    return;
  }

  const takeOtpk = db.prepare(`SELECT key_id, public_key FROM one_time_prekeys WHERE device_id = ? ORDER BY key_id ASC LIMIT 1`);
  const deleteOtpk = db.prepare(`DELETE FROM one_time_prekeys WHERE device_id = ? AND key_id = ?`);

  const bundles = db.transaction(() =>
    devices.map((d) => {
      const otpk = takeOtpk.get(d.id) as { key_id: number; public_key: Buffer } | undefined;
      if (otpk) deleteOtpk.run(d.id, otpk.key_id);
      return {
        deviceId: d.id,
        identitySigningKey: account.identity_signing_public_key.toString("base64"),
        identityDhKey: account.identity_dh_public_key.toString("base64"),
        signedPreKeyId: d.signed_prekey_id,
        signedPreKeyPublic: d.signed_prekey_public.toString("base64"),
        signedPreKeySignature: d.signed_prekey_signature.toString("base64"),
        oneTimePreKeyId: otpk?.key_id,
        oneTimePreKeyPublic: otpk ? otpk.public_key.toString("base64") : undefined,
      };
    }),
  )();

  res.json({ bundles });
});

keysRouter.get("/prekeys/count", requireAuth, (req, res) => {
  const row = db.prepare(`SELECT COUNT(*) as n FROM one_time_prekeys WHERE device_id = ?`).get(req.session!.deviceId) as { n: number };
  res.json({ remaining: row.n });
});

const topUpSchema = z.object({
  oneTimePreKeys: z
    .array(z.object({ keyId: z.number().int().nonnegative(), publicKey: z.string() }))
    .min(1)
    .max(200),
});

keysRouter.post("/prekeys", requireAuth, (req, res) => {
  const parsed = topUpSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const insert = db.prepare(`INSERT OR IGNORE INTO one_time_prekeys (device_id, key_id, public_key, created_at) VALUES (?, ?, ?, ?)`);
  const now = Date.now();
  const tx = db.transaction(() => {
    for (const otpk of parsed.data.oneTimePreKeys) {
      if (b64ToBuffer(otpk.publicKey).length !== 32) throw new Error("bad prekey length");
      insert.run(req.session!.deviceId, otpk.keyId, b64ToBuffer(otpk.publicKey), now);
    }
  });
  try {
    tx();
  } catch {
    res.status(400).json({ error: "invalid prekey data" });
    return;
  }
  res.status(201).json({ added: parsed.data.oneTimePreKeys.length });
});

const rotateSpkSchema = z.object({
  signedPreKeyId: z.number().int().nonnegative(),
  signedPreKeyPublic: z.string(),
  signedPreKeySignature: z.string(),
});

keysRouter.post("/signed-prekey", requireAuth, (req, res) => {
  const parsed = rotateSpkSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const account = db.prepare(`SELECT identity_signing_public_key FROM accounts a JOIN devices d ON d.account_id = a.id WHERE d.id = ?`).get(
    req.session!.deviceId,
  ) as { identity_signing_public_key: Buffer } | undefined;
  if (!account) {
    res.status(404).json({ error: "device not found" });
    return;
  }

  const spkPublic = b64ToBuffer(parsed.data.signedPreKeyPublic);
  const signature = b64ToBuffer(parsed.data.signedPreKeySignature);
  const sigOk = verifySignedPreKey(new Uint8Array(account.identity_signing_public_key), new Uint8Array(spkPublic), new Uint8Array(signature));
  if (!sigOk) {
    res.status(400).json({ error: "signature does not verify against this account's identity key" });
    return;
  }

  db.prepare(
    `UPDATE devices SET signed_prekey_id = ?, signed_prekey_public = ?, signed_prekey_signature = ?, signed_prekey_created_at = ? WHERE id = ?`,
  ).run(parsed.data.signedPreKeyId, spkPublic, signature, Date.now(), req.session!.deviceId);

  res.json({ ok: true });
});
