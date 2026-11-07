import {
  ratchetEncrypt,
  ratchetDecrypt,
  toBase64,
  fromBase64,
  utf8,
  fromUtf8,
  type IdentityKeyPair,
  type RatchetHeader,
  type DoubleRatchetState,
} from "@e2e-chat/crypto";
import { db, type MessageRow, type ContactRow, type OutboxRow } from "./db.js";
import { vault } from "./vault.js";
import { api } from "./api.js";
import { randomUUID } from "./uuid.js";
import { padMessage, unpadMessage } from "./padding.js";
import { getSession, putSession, initiateSession, respondToSession, fetchDeviceBundles, type PreKeyMessageHeader } from "./sessions.js";
import { replenishPreKeysIfNeeded } from "./identity.js";
import type { GatewayEvent } from "./ws.js";

interface WireHeader {
  dhPublicKey: string; // base64
  previousChainLength: number;
  messageNumber: number;
}

interface WireMessage {
  header: WireHeader;
  ciphertext: string; // base64
  preKeyHeader?: PreKeyMessageHeader;
}

export interface PlaintextPayload {
  kind: "text" | "attachment" | "system";
  text?: string;
  attachment?: { attachmentId: string; filename: string; mimeType: string; size: number; decryptionKey: string };
  sentAt: number;
  disappearingSeconds?: number;
}

function toWireHeader(h: RatchetHeader): WireHeader {
  return { dhPublicKey: toBase64(h.dhPublicKey), previousChainLength: h.previousChainLength, messageNumber: h.messageNumber };
}

function fromWireHeader(h: WireHeader): RatchetHeader {
  return { dhPublicKey: fromBase64(h.dhPublicKey), previousChainLength: h.previousChainLength, messageNumber: h.messageNumber };
}

/** Encrypts and sends `payload` to every device of `contact` we currently
 * have (or can establish) a session with. Fans out one independently
 * encrypted copy per recipient device, which is the normal (not a bug)
 * multi-device behavior for a pairwise ratchet. */
export async function sendToContact(identity: IdentityKeyPair, selfAccountId: string, contact: ContactRow, payload: PlaintextPayload): Promise<void> {
  const deviceIds = await deliverRawToAccount(identity, contact.accountId, contact.username, padMessage(utf8(JSON.stringify(payload))));
  await persistOutgoing(contact.accountId, selfAccountId, payload);
  if (deviceIds.length === 0) {
    await db.outbox.put({ id: randomUUID(), conversationId: contact.accountId, isGroup: false, createdAt: Date.now(), payload });
  }
}

/** Low-level fan-out: encrypts `plaintext` once per device of `accountId`
 * (establishing a fresh X3DH session per device the first time) and sends
 * it as envelopeType "prekey"/"ratchet". Used directly by sendToContact for
 * chat messages, and by groups.ts to deliver Sender Key distributions over
 * the same pairwise sessions. Returns the device ids reached. */
export async function deliverRawToAccount(identity: IdentityKeyPair, accountId: string, username: string, plaintext: Uint8Array): Promise<string[]> {
  let deviceIds = (await db.deviceSessions.where("contactAccountId").equals(accountId).toArray()).map((r) => r.deviceId);

  if (deviceIds.length === 0) {
    const bundles = await fetchDeviceBundles(username);
    for (const bundle of bundles) {
      const { state, preKeyHeader } = initiateSession(identity, bundle);
      await sendEnvelope(bundle.deviceId, accountId, state, plaintext, preKeyHeader);
    }
    deviceIds = bundles.map((b) => b.deviceId);
  } else {
    for (const deviceId of deviceIds) {
      const state = await getSession(deviceId);
      if (!state) continue;
      await sendEnvelope(deviceId, accountId, state, plaintext);
    }
  }
  return deviceIds;
}

async function sendEnvelope(
  deviceId: string,
  contactAccountId: string,
  state: DoubleRatchetState,
  plaintext: Uint8Array,
  preKeyHeader?: PreKeyMessageHeader,
): Promise<void> {
  const { header, ciphertext } = ratchetEncrypt(state, plaintext);
  const wire: WireMessage = { header: toWireHeader(header), ciphertext: toBase64(ciphertext), preKeyHeader };
  const body = toBase64(utf8(JSON.stringify(wire)));

  await api.post("/api/messages", {
    toDeviceId: deviceId,
    envelopeType: preKeyHeader ? "prekey" : "ratchet",
    ciphertext: body,
  });

  await putSession(deviceId, contactAccountId, state);
}

async function persistOutgoing(conversationId: string, selfAccountId: string, payload: PlaintextPayload): Promise<void> {
  const row: MessageRow = {
    id: randomUUID(),
    conversationId,
    isGroup: false,
    direction: "out",
    senderAccountId: selfAccountId,
    kind: payload.kind,
    encryptedBody: vault.encryptJSON(payload),
    createdAt: payload.sentAt,
    expiresAt: payload.disappearingSeconds ? payload.sentAt + payload.disappearingSeconds * 1000 : null,
    deliveredAt: Date.now(),
    readAt: null,
    deletedForEveryone: false,
  };
  await db.messages.put(row);
}

type IncomingMessage = Extract<GatewayEvent, { type: "message" }>["message"];

/** Decrypts any inbound message that travels over a pairwise Double Ratchet
 * session — covers both envelopeType "prekey"/"ratchet" (ordinary 1:1 chat)
 * and "senderkey-distribution" (a group Sender Key handed to this device
 * over its 1:1 session with the distributing member). Bootstraps a new
 * session from the X3DH header when one isn't established yet. Returns
 * null for anything this client can't decrypt (no session/header, or a
 * sealed-sender envelope, which isn't yet unwrapped client-side). */
export async function decryptEnvelope(identity: IdentityKeyPair, message: IncomingMessage): Promise<Uint8Array | null> {
  if (!message.fromAccountId || !message.fromDeviceId) return null;

  const wire = JSON.parse(fromUtf8(fromBase64(message.ciphertext))) as WireMessage;

  let state = await getSession(message.fromDeviceId);
  if (!state && wire.preKeyHeader) {
    state = await respondToSession(identity, wire.preKeyHeader);
  }
  if (!state) return null;

  const plaintext = unpadMessage(ratchetDecrypt(state, { header: fromWireHeader(wire.header), ciphertext: fromBase64(wire.ciphertext) }));
  await putSession(message.fromDeviceId, message.fromAccountId, state);

  if (wire.preKeyHeader) void replenishPreKeysIfNeeded(identity.signing.privateKey);
  return plaintext;
}

/** Decrypts an inbound 1:1 chat message pushed over the gateway (or
 * returned by the catch-up poll) and persists it. Returns the stored row,
 * or null if it wasn't a decryptable 1:1 chat message. */
export async function receiveMessage(identity: IdentityKeyPair, event: Extract<GatewayEvent, { type: "message" }>): Promise<MessageRow | null> {
  const { message } = event;
  if (!["prekey", "ratchet"].includes(message.envelopeType)) return null;

  const plaintext = await decryptEnvelope(identity, message);
  if (!plaintext || !message.fromAccountId) return null;

  const payload = JSON.parse(fromUtf8(plaintext)) as PlaintextPayload;
  const row: MessageRow = {
    id: message.id,
    conversationId: message.fromAccountId,
    isGroup: false,
    direction: "in",
    senderAccountId: message.fromAccountId,
    kind: payload.kind,
    encryptedBody: vault.encryptJSON(payload),
    createdAt: message.createdAt,
    expiresAt: payload.disappearingSeconds ? message.createdAt + payload.disappearingSeconds * 1000 : null,
    deliveredAt: Date.now(),
    readAt: null,
    deletedForEveryone: false,
  };
  await db.messages.put(row);
  return row;
}

export function readPlaintext(row: MessageRow): PlaintextPayload {
  return vault.decryptJSON<PlaintextPayload>(row.encryptedBody);
}

export type { OutboxRow };
