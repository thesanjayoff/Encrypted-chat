import {
  x3dhInitiate,
  x3dhRespond,
  ratchetInitAlice,
  ratchetInitBob,
  verifySignedPreKey,
  DoubleRatchetState,
  toBase64,
  fromBase64,
  type IdentityKeyPair,
  type SignedPreKey,
  type OneTimePreKey,
} from "@e2e-chat/crypto";
import { db, type DeviceSessionRow } from "./db.js";
import { vault } from "./vault.js";
import { api } from "./api.js";
import { loadPreKeyPrivate, consumeOneTimePreKey } from "./identity.js";

export interface DeviceBundle {
  deviceId: string;
  identitySigningKey: string;
  identityDhKey: string;
  signedPreKeyId: number;
  signedPreKeyPublic: string;
  signedPreKeySignature: string;
  oneTimePreKeyId?: number;
  oneTimePreKeyPublic?: string;
}

/** First message of a new session, carried alongside the first ciphertext
 * as envelopeType "prekey" — everything the recipient needs to recompute
 * the same X3DH shared secret and initialize their side of the ratchet. */
export interface PreKeyMessageHeader {
  identityDhKey: string; // base64, initiator's long-term DH public key
  ephemeralKey: string; // base64, initiator's one-time X3DH ephemeral public key
  signedPreKeyId: number; // which of the responder's SPKs was used
  oneTimePreKeyId?: number; // which of the responder's OTPKs was used, if any
}

export async function fetchDeviceBundles(username: string): Promise<DeviceBundle[]> {
  const res = await api.get<{ bundles: DeviceBundle[] }>(`/api/keys/bundles/${encodeURIComponent(username)}`);
  return res.bundles;
}

export async function getSession(deviceId: string): Promise<DoubleRatchetState | null> {
  const row = await db.deviceSessions.get(deviceId);
  if (!row) return null;
  const json = vault.decryptJSON<ReturnType<DoubleRatchetState["toJSON"]>>(row.encryptedState);
  return DoubleRatchetState.fromJSON(json);
}

export async function putSession(deviceId: string, contactAccountId: string, state: DoubleRatchetState): Promise<void> {
  const existing = await db.deviceSessions.get(deviceId);
  const now = Date.now();
  const row: DeviceSessionRow = {
    deviceId,
    contactAccountId,
    encryptedState: vault.encryptJSON(state.toJSON()),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  await db.deviceSessions.put(row);
}

/** Alice's side: start a brand-new outgoing session with one of a contact's
 * devices by consuming its published prekey bundle. The caller must send
 * the returned `preKeyHeader` alongside the first ciphertext so the
 * recipient (Bob) can derive the same session (envelopeType "prekey"). */
export function initiateSession(
  identity: IdentityKeyPair,
  bundle: DeviceBundle,
): { state: DoubleRatchetState; preKeyHeader: PreKeyMessageHeader } {
  const responderBundle = {
    identitySigningKey: fromBase64(bundle.identitySigningKey),
    identityDhKey: fromBase64(bundle.identityDhKey),
    signedPreKeyId: bundle.signedPreKeyId,
    signedPreKeyPublic: fromBase64(bundle.signedPreKeyPublic),
    signedPreKeySignature: fromBase64(bundle.signedPreKeySignature),
    oneTimePreKeyId: bundle.oneTimePreKeyId,
    oneTimePreKeyPublic: bundle.oneTimePreKeyPublic ? fromBase64(bundle.oneTimePreKeyPublic) : undefined,
  };

  // x3dhInitiate re-verifies the SPK signature itself (and throws
  // X3DHVerificationError if it fails) — this is exactly what makes a
  // substituted signed prekey from a malicious/compromised server
  // detectable rather than silently accepted.
  const { sharedSecret, associatedData, ephemeralKeyPair } = x3dhInitiate(identity, responderBundle);
  const state = ratchetInitAlice(sharedSecret, associatedData, responderBundle.signedPreKeyPublic);

  return {
    state,
    preKeyHeader: {
      identityDhKey: toBase64(identity.dh.publicKey),
      ephemeralKey: toBase64(ephemeralKeyPair.publicKey),
      signedPreKeyId: bundle.signedPreKeyId,
      oneTimePreKeyId: bundle.oneTimePreKeyId,
    },
  };
}

/** Bob's side: derive the session from an incoming "prekey" message header.
 * Looks up (and, for a one-time prekey, immediately consumes) this
 * device's own locally-stored prekey private keys. */
export async function respondToSession(identity: IdentityKeyPair, header: PreKeyMessageHeader): Promise<DoubleRatchetState> {
  const spkPair = await loadPreKeyPrivate("signed", header.signedPreKeyId);
  if (!spkPair) throw new Error("Unknown signed prekey id — cannot establish session");
  const signedPreKey: SignedPreKey = { keyId: header.signedPreKeyId, keyPair: spkPair, signature: new Uint8Array(0) };

  let oneTimePreKey: OneTimePreKey | undefined;
  if (header.oneTimePreKeyId !== undefined) {
    const otpkPair = await loadPreKeyPrivate("oneTime", header.oneTimePreKeyId);
    if (otpkPair) oneTimePreKey = { keyId: header.oneTimePreKeyId, keyPair: otpkPair };
  }

  const { sharedSecret, associatedData } = x3dhRespond(
    identity,
    signedPreKey,
    oneTimePreKey,
    fromBase64(header.identityDhKey),
    fromBase64(header.ephemeralKey),
  );
  const state = ratchetInitBob(sharedSecret, associatedData, spkPair);

  if (header.oneTimePreKeyId !== undefined) await consumeOneTimePreKey(header.oneTimePreKeyId);
  return state;
}

export { verifySignedPreKey };
