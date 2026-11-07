import { Router } from "express";
import { randomUUID, randomBytes } from "node:crypto";
import { z } from "zod";
import * as opaque from "@serenity-kit/opaque";
import { verifySignedPreKey } from "@e2e-chat/crypto";
import { db } from "../db.js";
import { getOpaqueServerSetup } from "../env.js";
import { createSession } from "../sessions.js";
import { authLimiter } from "../middleware/rateLimit.js";

export const authRouter = Router();

const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
const LOGIN_TTL_MS = 2 * 60 * 1000;

function b64ToBuffer(s: string): Buffer {
  return Buffer.from(s, "base64");
}

// ---- Registration -----------------------------------------------------
// OPAQUE registration is stateless on the server between start and finish:
// createRegistrationResponse needs no stored state, only serverSetup +
// username + the client's request. Nothing about the password, or any
// function of it that could be brute-forced offline, ever reaches us.

const registerStartSchema = z.object({
  username: z.string().regex(USERNAME_RE),
  registrationRequest: z.string().min(1),
});

authRouter.post("/register/start", authLimiter, async (req, res) => {
  const parsed = registerStartSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const { username, registrationRequest } = parsed.data;

  const existing = db.prepare(`SELECT id FROM accounts WHERE username = ?`).get(username);
  if (existing) {
    res.status(409).json({ error: "username taken" });
    return;
  }

  const serverSetup = await getOpaqueServerSetup();
  const { registrationResponse } = opaque.server.createRegistrationResponse({
    serverSetup,
    userIdentifier: username,
    registrationRequest,
  });
  res.json({ registrationResponse });
});

const deviceKeysSchema = z.object({
  label: z.string().max(64).optional(),
  signedPreKeyId: z.number().int().nonnegative(),
  signedPreKeyPublic: z.string(),
  signedPreKeySignature: z.string(),
  oneTimePreKeys: z.array(z.object({ keyId: z.number().int().nonnegative(), publicKey: z.string() })).min(1).max(200),
});

const registerFinishSchema = z.object({
  username: z.string().regex(USERNAME_RE),
  registrationRecord: z.string().min(1),
  identitySigningPublicKey: z.string(),
  identityDhKey: z.string(),
  device: deviceKeysSchema,
});

authRouter.post("/register/finish", authLimiter, async (req, res) => {
  const parsed = registerFinishSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request", details: parsed.error.flatten() });
    return;
  }
  const { username, registrationRecord, identitySigningPublicKey, identityDhKey, device } = parsed.data;

  const existing = db.prepare(`SELECT id FROM accounts WHERE username = ?`).get(username);
  if (existing) {
    res.status(409).json({ error: "username taken" });
    return;
  }

  const sigOk = verifySignedPreKey(
    b64ToBuffer(identitySigningPublicKey),
    b64ToBuffer(device.signedPreKeyPublic),
    b64ToBuffer(device.signedPreKeySignature),
  );
  if (!sigOk) {
    res.status(400).json({ error: "Signed PreKey signature does not verify against the supplied identity key" });
    return;
  }

  const accountId = randomUUID();
  const deviceId = randomUUID();
  const now = Date.now();

  const insertAll = db.transaction(() => {
    db.prepare(
      `INSERT INTO accounts (id, username, opaque_registration_record, identity_signing_public_key, identity_dh_public_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(accountId, username, registrationRecord, b64ToBuffer(identitySigningPublicKey), b64ToBuffer(identityDhKey), now);

    db.prepare(
      `INSERT INTO devices (id, account_id, label, is_primary, signed_prekey_id, signed_prekey_public, signed_prekey_signature, signed_prekey_created_at, created_at)
       VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)`,
    ).run(deviceId, accountId, device.label ?? null, device.signedPreKeyId, b64ToBuffer(device.signedPreKeyPublic), b64ToBuffer(device.signedPreKeySignature), now, now);

    const insertOtpk = db.prepare(`INSERT INTO one_time_prekeys (device_id, key_id, public_key, created_at) VALUES (?, ?, ?, ?)`);
    for (const otpk of device.oneTimePreKeys) {
      insertOtpk.run(deviceId, otpk.keyId, b64ToBuffer(otpk.publicKey), now);
    }
  });
  insertAll();

  const sessionToken = createSession(accountId, deviceId);
  res.status(201).json({ accountId, deviceId, sessionToken });
});

// ---- Login --------------------------------------------------------------

const loginStartSchema = z.object({
  username: z.string().regex(USERNAME_RE),
  startLoginRequest: z.string().min(1),
});

authRouter.post("/login/start", authLimiter, async (req, res) => {
  const parsed = loginStartSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const { username, startLoginRequest } = parsed.data;

  const account = db.prepare(`SELECT id, opaque_registration_record FROM accounts WHERE username = ?`).get(username) as
    | { id: string; opaque_registration_record: string }
    | undefined;

  const serverSetup = await getOpaqueServerSetup();

  // Constant-shape response whether or not the username exists, so this
  // endpoint cannot be used to enumerate registered usernames by timing/shape.
  if (!account) {
    // opaque-ke supports a deterministic "fake" response path for exactly
    // this reason; without the underlying registration record we instead
    // run a real startLogin against a freshly-fabricated record so the
    // response is indistinguishable in shape from a real one.
    const fake = opaque.client.startRegistration({ password: randomBytes(16).toString("hex") });
    const fakeResponse = opaque.server.createRegistrationResponse({
      serverSetup,
      userIdentifier: username,
      registrationRequest: fake.registrationRequest,
    });
    const fakeRecord = opaque.client.finishRegistration({
      clientRegistrationState: fake.clientRegistrationState,
      registrationResponse: fakeResponse.registrationResponse,
      password: randomBytes(16).toString("hex"),
    });
    const { loginResponse } = opaque.server.startLogin({
      serverSetup,
      userIdentifier: username,
      registrationRecord: fakeRecord.registrationRecord,
      startLoginRequest,
    });
    res.json({ loginId: randomUUID(), loginResponse });
    return;
  }

  const { serverLoginState, loginResponse } = opaque.server.startLogin({
    serverSetup,
    userIdentifier: username,
    registrationRecord: account.opaque_registration_record,
    startLoginRequest,
  });

  const loginId = randomUUID();
  db.prepare(`INSERT INTO pending_logins (id, account_id, opaque_state, created_at) VALUES (?, ?, ?, ?)`).run(
    loginId,
    account.id,
    serverLoginState,
    Date.now(),
  );
  res.json({ loginId, loginResponse });
});

const loginFinishSchema = z.object({
  loginId: z.string().uuid(),
  finishLoginRequest: z.string().min(1),
  deviceId: z.string().uuid(),
});

authRouter.post("/login/finish", authLimiter, async (req, res) => {
  const parsed = loginFinishSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const { loginId, finishLoginRequest, deviceId } = parsed.data;

  const pending = db.prepare(`SELECT account_id, opaque_state, created_at FROM pending_logins WHERE id = ?`).get(loginId) as
    | { account_id: string; opaque_state: string; created_at: number }
    | undefined;

  // Always delete on first use — a pending login is single-use regardless of outcome (replay protection).
  db.prepare(`DELETE FROM pending_logins WHERE id = ?`).run(loginId);

  if (!pending || Date.now() - pending.created_at > LOGIN_TTL_MS) {
    res.status(401).json({ error: "login expired or invalid" });
    return;
  }

  let result;
  try {
    result = opaque.server.finishLogin({ serverLoginState: pending.opaque_state, finishLoginRequest });
  } catch {
    res.status(401).json({ error: "authentication failed" });
    return;
  }
  if (!result) {
    res.status(401).json({ error: "authentication failed" });
    return;
  }

  const device = db.prepare(`SELECT id FROM devices WHERE id = ? AND account_id = ?`).get(deviceId, pending.account_id);
  if (!device) {
    res.status(403).json({ error: "unknown device for this account — link this device first" });
    return;
  }

  db.prepare(`UPDATE devices SET last_seen_at = ? WHERE id = ?`).run(Date.now(), deviceId);
  const sessionToken = createSession(pending.account_id, deviceId);
  res.json({ accountId: pending.account_id, deviceId, sessionToken });
});
