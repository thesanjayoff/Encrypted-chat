import {
  createSenderKeyState,
  receiveSenderKeyDistribution,
  senderKeyEncrypt,
  senderKeyDecrypt,
  SenderKeyState,
  toBase64,
  fromBase64,
  utf8,
  fromUtf8,
  type IdentityKeyPair,
} from "@e2e-chat/crypto";
import { db, type GroupRow, type GroupSenderKeyRow, type MessageRow } from "./db.js";
import { vault } from "./vault.js";
import { api } from "./api.js";
import { randomUUID } from "./uuid.js";
import { padMessage, unpadMessage } from "./padding.js";
import { deliverRawToAccount, decryptEnvelope, type PlaintextPayload } from "./messaging.js";
import type { GatewayEvent } from "./ws.js";

interface DistributionWire {
  kind: "senderkey-distribution";
  groupId: string;
  chainKey: string; // base64
  signingPublicKey: string; // base64
  iteration: number;
  // The server never learns a group's name, so the creator (and anyone else
  // rotating their key) carries along whatever name they have locally —
  // this is the only channel a new or rejoining member learns it through.
  groupName?: string;
}

interface GroupMessageWire {
  iteration: number;
  ciphertext: string; // base64
  signature: string; // base64
}

interface ContactLookup {
  accountId: string;
  username: string;
}

/** Creates a group on the server (member list only — the server never
 * learns a group name), then generates this device's Sender Key and
 * distributes it to every other member over their 1:1 sessions. */
export async function createGroup(
  identity: IdentityKeyPair,
  selfAccountId: string,
  name: string,
  members: ContactLookup[],
): Promise<GroupRow> {
  const res = await api.post<{ groupId: string; members: string[] }>("/api/groups", {
    memberUsernames: members.map((m) => m.username),
  });

  const row: GroupRow = { groupId: res.groupId, name, memberAccountIds: res.members, createdAt: Date.now() };
  await db.groups.put(row);

  await rotateAndDistribute(identity, selfAccountId, row.groupId, members);
  return row;
}

async function storeOwnSenderKey(groupId: string, accountId: string, state: SenderKeyState): Promise<void> {
  const row: GroupSenderKeyRow = {
    id: `${groupId}:${accountId}`,
    groupId,
    accountId,
    isOwn: true,
    encryptedState: vault.encryptJSON(state.toJSON()),
    updatedAt: Date.now(),
  };
  await db.groupSenderKeys.put(row);
}

/** Generates a brand-new Sender Key (fresh chain + signing key) for this
 * device in this group and distributes it to the given members — call on
 * group creation and again any time membership changes, so a removed
 * member's old key can never decrypt what's sent after the rotation. */
export async function rotateAndDistribute(identity: IdentityKeyPair, selfAccountId: string, groupId: string, members: ContactLookup[]): Promise<void> {
  const { state, distribution } = createSenderKeyState();
  await storeOwnSenderKey(groupId, selfAccountId, state);

  const localGroup = await db.groups.get(groupId);
  const wire: DistributionWire = {
    kind: "senderkey-distribution",
    groupId,
    chainKey: toBase64(distribution.chainKey),
    signingPublicKey: toBase64(distribution.signingPublicKey),
    iteration: distribution.iteration,
    groupName: localGroup?.name,
  };
  const plaintext = padMessage(utf8(JSON.stringify(wire)));

  for (const member of members) {
    if (member.accountId === selfAccountId) continue;
    await deliverRawToAccount(identity, member.accountId, member.username, plaintext, "senderkey-distribution");
  }
}

/** Handles an inbound envelopeType "senderkey-distribution" message: stores
 * the sender's new Sender Key for this group, replacing any previous one
 * (a rotation always supersedes the key it replaces). */
export async function handleDistribution(identity: IdentityKeyPair, message: Parameters<typeof decryptEnvelope>[1]): Promise<void> {
  const plaintext = await decryptEnvelope(identity, message);
  if (!plaintext || !message.fromAccountId) return;
  // decryptEnvelope already un-pads (it's shared with 1:1 chat decryption).
  const wire = JSON.parse(fromUtf8(plaintext)) as DistributionWire;
  if (wire.kind !== "senderkey-distribution") return;

  const state = receiveSenderKeyDistribution({
    chainKey: fromBase64(wire.chainKey),
    signingPublicKey: fromBase64(wire.signingPublicKey),
    iteration: wire.iteration,
  });

  const row: GroupSenderKeyRow = {
    id: `${wire.groupId}:${message.fromAccountId}`,
    groupId: wire.groupId,
    accountId: message.fromAccountId,
    isOwn: false,
    encryptedState: vault.encryptJSON(state.toJSON()),
    updatedAt: Date.now(),
  };
  await db.groupSenderKeys.put(row);

  if (wire.groupName) {
    // Atomic read-modify-write: this races against this same account's own
    // "control" membership-changed notification (the server notifies every
    // member, including whoever just created/changed the group) touching
    // the same db.groups row. Without a single transaction, an interleaved
    // read-before-write from either side can silently drop the other's field.
    await db.transaction("rw", db.groups, async () => {
      const existing = await db.groups.get(wire.groupId);
      await db.groups.put({
        groupId: wire.groupId,
        name: wire.groupName!,
        memberAccountIds: existing?.memberAccountIds ?? [],
        createdAt: existing?.createdAt ?? Date.now(),
        disappearingSeconds: existing?.disappearingSeconds,
      });
    });
  }
}

async function loadSenderKey(groupId: string, accountId: string): Promise<SenderKeyState | null> {
  const row = await db.groupSenderKeys.get(`${groupId}:${accountId}`);
  if (!row) return null;
  return SenderKeyState.fromJSON(vault.decryptJSON(row.encryptedState));
}

async function saveSenderKey(groupId: string, accountId: string, isOwn: boolean, state: SenderKeyState): Promise<void> {
  await db.groupSenderKeys.put({
    id: `${groupId}:${accountId}`,
    groupId,
    accountId,
    isOwn,
    encryptedState: vault.encryptJSON(state.toJSON()),
    updatedAt: Date.now(),
  });
}

/** Encrypts and fans a text/attachment payload out to every current member
 * via the group's server-side fan-out endpoint. Requires this device to
 * already have generated its own Sender Key for the group (via
 * rotateAndDistribute, run at group creation / on joining). */
export async function sendGroupMessage(selfAccountId: string, groupId: string, payload: PlaintextPayload): Promise<void> {
  payload.id ??= randomUUID();
  const state = await loadSenderKey(groupId, selfAccountId);
  if (!state) throw new Error("No local Sender Key for this group yet — call rotateAndDistribute first");

  const plaintext = padMessage(utf8(JSON.stringify(payload)));
  const { iteration, ciphertext, signature } = senderKeyEncrypt(state, plaintext);
  await saveSenderKey(groupId, selfAccountId, true, state);

  const wire: GroupMessageWire = { iteration, ciphertext: toBase64(ciphertext), signature: toBase64(signature) };
  await api.post(`/api/groups/${groupId}/messages`, { ciphertext: toBase64(utf8(JSON.stringify(wire))) });

  if (payload.kind === "delete-request" && payload.targetMessageId) {
    await db.messages.update(payload.targetMessageId, { deletedForEveryone: true });
  } else {
    await persistGroupMessage(groupId, selfAccountId, payload);
  }
}

/** Sends a "delete for everyone" request for a group message this device
 * sent earlier, and marks the local copy deleted immediately. */
export async function requestGroupDeleteForEveryone(selfAccountId: string, groupId: string, messageId: string): Promise<void> {
  await sendGroupMessage(selfAccountId, groupId, { kind: "delete-request", targetMessageId: messageId, sentAt: Date.now() });
}

async function persistGroupMessage(groupId: string, selfAccountId: string, payload: PlaintextPayload): Promise<void> {
  const row: MessageRow = {
    id: payload.id ?? randomUUID(),
    conversationId: groupId,
    isGroup: true,
    direction: "out",
    senderAccountId: selfAccountId,
    kind: payload.kind as "text" | "attachment" | "system",
    encryptedBody: vault.encryptJSON(payload),
    createdAt: payload.sentAt,
    expiresAt: payload.disappearingSeconds ? payload.sentAt + payload.disappearingSeconds * 1000 : null,
    deliveredAt: Date.now(),
    readAt: null,
    deletedForEveryone: false,
  };
  await db.messages.put(row);
}

/** Handles an inbound envelopeType "senderkey" group chat message. The
 * sender's per-message Ed25519 signature (verified inside
 * senderKeyDecrypt) is what stops any other member who also holds the
 * shared chain key from forging a message as this sender. */
export async function handleGroupMessage(
  event: Extract<GatewayEvent, { type: "message" }>,
): Promise<MessageRow | null> {
  const { message } = event;
  if (message.envelopeType !== "senderkey" || !message.fromAccountId) return null;

  const wire = JSON.parse(fromUtf8(fromBase64(message.ciphertext))) as GroupMessageWire;
  const groupId = await resolveGroupIdForSender(message.fromAccountId);
  if (!groupId) return null;

  const state = await loadSenderKey(groupId, message.fromAccountId);
  if (!state) return null; // haven't received this member's distribution yet

  const plaintext = unpadMessage(senderKeyDecrypt(state, { iteration: wire.iteration, ciphertext: fromBase64(wire.ciphertext), signature: fromBase64(wire.signature) }));
  await saveSenderKey(groupId, message.fromAccountId, false, state);

  const payload = JSON.parse(fromUtf8(plaintext)) as PlaintextPayload;

  if (payload.kind === "delete-request") {
    if (payload.targetMessageId) {
      const target = await db.messages.get(payload.targetMessageId);
      if (target && target.senderAccountId === message.fromAccountId) {
        await db.messages.update(payload.targetMessageId, { deletedForEveryone: true });
      }
    }
    return null;
  }

  const row: MessageRow = {
    id: payload.id ?? message.id,
    conversationId: groupId,
    isGroup: true,
    direction: "in",
    senderAccountId: message.fromAccountId,
    kind: payload.kind as "text" | "attachment" | "system",
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

/** There's no groupId on the wire for a "senderkey" message (the server
 * already knows which group routed it to us, but doesn't pass that through
 * — see limitation note). We disambiguate by checking which of our known
 * groups this sender belongs to and for which we hold their distribution.
 * A member of more than one shared group with us is a known limitation;
 * see THREAT_MODEL.md / README. */
async function resolveGroupIdForSender(accountId: string): Promise<string | null> {
  const keys = await db.groupSenderKeys.where("accountId").equals(accountId).toArray();
  return keys[0]?.groupId ?? null;
}

interface MembershipChangedControl {
  kind: "group-membership-changed";
  groupId: string;
  members: string[];
}

/** envelopeType "control" membership-change notifications are sent by the
 * server in cleartext JSON (membership is server-visible by necessity —
 * it's what the fan-out is computed from), so this just updates the local
 * membership cache; it does NOT rotate/redistribute on its own. The member
 * who performed the add/remove is responsible for calling
 * rotateAndDistribute so a removed member loses access going forward. */
export async function handleMembershipChanged(message: Extract<GatewayEvent, { type: "message" }>["message"]): Promise<void> {
  if (message.envelopeType !== "control") return;
  const control = JSON.parse(fromUtf8(fromBase64(message.ciphertext))) as MembershipChangedControl;
  if (control.kind !== "group-membership-changed") return;
  // Same atomicity concern as handleDistribution's groupName write above —
  // this and that both read-then-write the same db.groups row and the
  // server fans this notification out to every member, including the
  // account that triggered it.
  await db.transaction("rw", db.groups, async () => {
    const existing = await db.groups.get(control.groupId);
    await db.groups.put({
      groupId: control.groupId,
      name: existing?.name ?? "",
      memberAccountIds: control.members,
      createdAt: existing?.createdAt ?? Date.now(),
      disappearingSeconds: existing?.disappearingSeconds,
    });
  });
}
