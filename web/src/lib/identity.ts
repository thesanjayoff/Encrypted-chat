import {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKeys,
  toBase64,
  fromBase64,
  type IdentityKeyPair,
  type KeyPair,
  type SignedPreKey,
  type OneTimePreKey,
} from "@e2e-chat/crypto";
import { db, type IdentityRow, type PreKeyRow } from "./db.js";
import { vault } from "./vault.js";
import { api } from "./api.js";

async function storePreKeyPrivate(kind: "signed" | "oneTime", keyId: number, publicKey: Uint8Array, privateKey: Uint8Array): Promise<void> {
  const row: PreKeyRow = {
    id: `${kind === "signed" ? "spk" : "otpk"}:${keyId}`,
    kind,
    keyId,
    publicKey: toBase64(publicKey),
    encryptedPrivateKey: vault.encryptJSON({ privateKey: toBase64(privateKey) }),
    createdAt: Date.now(),
  };
  await db.preKeys.put(row);
}

/** Looks up the private half of a signed or one-time prekey this device
 * previously published, needed to respond to an incoming X3DH "prekey"
 * message. Returns null if not found (e.g. an already-consumed or
 * long-expired one-time prekey — the sender should fall back or fail). */
export async function loadPreKeyPrivate(kind: "signed" | "oneTime", keyId: number): Promise<KeyPair | null> {
  const row = await db.preKeys.get(`${kind === "signed" ? "spk" : "otpk"}:${keyId}`);
  if (!row) return null;
  const { privateKey } = vault.decryptJSON<{ privateKey: string }>(row.encryptedPrivateKey);
  return { publicKey: fromBase64(row.publicKey), privateKey: fromBase64(privateKey) };
}

/** A one-time prekey must never be reused — delete our local copy of its
 * private key as soon as it's been consumed to respond to a session. */
export async function consumeOneTimePreKey(keyId: number): Promise<void> {
  await db.preKeys.delete(`otpk:${keyId}`);
}

export interface LoadedIdentity {
  accountId: string;
  username: string;
  deviceId: string;
  identity: IdentityKeyPair;
}

const OTPK_BATCH_SIZE = 20;
const OTPK_LOW_WATER_MARK = 10;

export async function createLocalIdentity(accountId: string, username: string, deviceId: string): Promise<{ row: IdentityRow; identity: IdentityKeyPair; signedPreKey: ReturnType<typeof generateSignedPreKey>; oneTimePreKeys: ReturnType<typeof generateOneTimePreKeys> }> {
  const identity = generateIdentityKeyPair();
  const signedPreKey = generateSignedPreKey(identity.signing.privateKey, 1);
  const oneTimePreKeys = generateOneTimePreKeys(1, OTPK_BATCH_SIZE);

  const row: IdentityRow = {
    id: "self",
    accountId,
    username,
    deviceId,
    signingPublicKey: toBase64(identity.signing.publicKey),
    dhPublicKey: toBase64(identity.dh.publicKey),
    encryptedPrivateKeys: vault.encryptJSON({
      signingPrivateKey: toBase64(identity.signing.privateKey),
      dhPrivateKey: toBase64(identity.dh.privateKey),
    }),
    nextSignedPreKeyId: 2,
    nextOneTimePreKeyId: OTPK_BATCH_SIZE + 1,
    createdAt: Date.now(),
  };
  await db.identity.put(row);
  await storePreKeyPrivate("signed", signedPreKey.keyId, signedPreKey.keyPair.publicKey, signedPreKey.keyPair.privateKey);
  for (const otpk of oneTimePreKeys) {
    await storePreKeyPrivate("oneTime", otpk.keyId, otpk.keyPair.publicKey, otpk.keyPair.privateKey);
  }
  return { row, identity, signedPreKey, oneTimePreKeys };
}

export async function loadLocalIdentity(): Promise<LoadedIdentity | null> {
  const row = await db.identity.get("self");
  if (!row) return null;
  const priv = vault.decryptJSON<{ signingPrivateKey: string; dhPrivateKey: string }>(row.encryptedPrivateKeys);
  const identity: IdentityKeyPair = {
    signing: { publicKey: fromBase64(row.signingPublicKey), privateKey: fromBase64(priv.signingPrivateKey) },
    dh: { publicKey: fromBase64(row.dhPublicKey), privateKey: fromBase64(priv.dhPrivateKey) },
  };
  return { accountId: row.accountId, username: row.username, deviceId: row.deviceId, identity };
}

export async function hasLocalIdentity(): Promise<boolean> {
  return (await db.identity.get("self")) !== undefined;
}

/** Tops up this device's one-time prekey pool if it's running low. Call
 * periodically (e.g. on app start and after sending/receiving). */
export async function replenishPreKeysIfNeeded(signingPrivateKey: Uint8Array): Promise<void> {
  const row = await db.identity.get("self");
  if (!row) return;
  const { remaining } = await api.get<{ remaining: number }>("/api/keys/prekeys/count");
  if (remaining >= OTPK_LOW_WATER_MARK) return;

  const startId = row.nextOneTimePreKeyId;
  const fresh = generateOneTimePreKeys(startId, OTPK_BATCH_SIZE);
  await api.post("/api/keys/prekeys", {
    oneTimePreKeys: fresh.map((k) => ({ keyId: k.keyId, publicKey: toBase64(k.keyPair.publicKey) })),
  });
  for (const otpk of fresh) {
    await storePreKeyPrivate("oneTime", otpk.keyId, otpk.keyPair.publicKey, otpk.keyPair.privateKey);
  }
  await db.identity.update("self", { nextOneTimePreKeyId: startId + OTPK_BATCH_SIZE });
  void signingPrivateKey; // reserved for signed-prekey rotation, which reuses this
}

export async function rotateSignedPreKey(identity: IdentityKeyPair): Promise<void> {
  const row = await db.identity.get("self");
  if (!row) return;
  const spk = generateSignedPreKey(identity.signing.privateKey, row.nextSignedPreKeyId);
  await api.post("/api/keys/signed-prekey", {
    signedPreKeyId: spk.keyId,
    signedPreKeyPublic: toBase64(spk.keyPair.publicKey),
    signedPreKeySignature: toBase64(spk.signature),
  });
  await storePreKeyPrivate("signed", spk.keyId, spk.keyPair.publicKey, spk.keyPair.privateKey);
  await db.identity.update("self", { nextSignedPreKeyId: row.nextSignedPreKeyId + 1 });
}

export type { KeyPair, SignedPreKey, OneTimePreKey };
