import Dexie, { type EntityTable } from "dexie";

/**
 * Local database schema. Columns suffixed `encrypted*` hold vault-sealed
 * blobs (see vault.ts) — base64 `nonce || ciphertext` strings, opaque
 * without the vault key. Everything else here (usernames, timestamps,
 * group membership lists) is local-only bookkeeping, not secret, and kept
 * plain so it stays queryable.
 */

export interface IdentityRow {
  id: "self";
  accountId: string;
  username: string;
  deviceId: string;
  signingPublicKey: string; // base64, public
  dhPublicKey: string; // base64, public
  encryptedPrivateKeys: string; // vault blob: { signingPrivateKey, dhPrivateKey } (base64 each)
  nextSignedPreKeyId: number;
  nextOneTimePreKeyId: number;
  createdAt: number;
}

export interface ContactRow {
  accountId: string;
  username: string;
  nickname?: string;
  addedAt: number;
  verified: boolean;
  identitySigningPublicKey: string; // base64 — cached so we can detect a key change
  identityDhPublicKey: string;
  disappearingSeconds?: number;
}

export interface PreKeyRow {
  id: string; // `spk:${keyId}` or `otpk:${keyId}`
  kind: "signed" | "oneTime";
  keyId: number;
  publicKey: string; // base64, public
  encryptedPrivateKey: string; // vault blob: { privateKey: base64 }
  createdAt: number;
}

export interface DeviceSessionRow {
  deviceId: string; // PK
  contactAccountId: string;
  encryptedState: string; // vault blob of DoubleRatchetState.toJSON()
  createdAt: number;
  updatedAt: number;
}

export interface GroupRow {
  groupId: string;
  name: string;
  memberAccountIds: string[];
  createdAt: number;
  disappearingSeconds?: number;
}

export interface GroupSenderKeyRow {
  id: string; // `${groupId}:${accountId}`
  groupId: string;
  accountId: string;
  isOwn: boolean;
  encryptedState: string; // vault blob of SenderKeyState.toJSON()
  updatedAt: number;
}

export interface MessageRow {
  id: string;
  conversationId: string; // contact accountId, or groupId
  isGroup: boolean;
  direction: "in" | "out";
  senderAccountId: string;
  kind: "text" | "attachment" | "system";
  encryptedBody: string; // vault blob of { text? } or { attachmentId, filename, mimeType, size, decryptionKey }
  createdAt: number;
  expiresAt: number | null;
  deliveredAt: number | null;
  readAt: number | null;
  deletedForEveryone: boolean;
}

export interface SettingsRow {
  key: string;
  value: unknown;
}

export interface OutboxRow {
  id: string;
  conversationId: string;
  isGroup: boolean;
  createdAt: number;
  payload: unknown; // whatever the sender needs to retry: plaintext, kind, etc. NOT persisted encrypted — see note in messaging.ts
}

const db = new Dexie("e2e-chat") as Dexie & {
  identity: EntityTable<IdentityRow, "id">;
  preKeys: EntityTable<PreKeyRow, "id">;
  contacts: EntityTable<ContactRow, "accountId">;
  deviceSessions: EntityTable<DeviceSessionRow, "deviceId">;
  groups: EntityTable<GroupRow, "groupId">;
  groupSenderKeys: EntityTable<GroupSenderKeyRow, "id">;
  messages: EntityTable<MessageRow, "id">;
  settings: EntityTable<SettingsRow, "key">;
  outbox: EntityTable<OutboxRow, "id">;
};

db.version(1).stores({
  identity: "id",
  preKeys: "id, kind, keyId",
  contacts: "accountId, username",
  deviceSessions: "deviceId, contactAccountId",
  groups: "groupId",
  groupSenderKeys: "id, groupId",
  messages: "id, conversationId, createdAt, expiresAt",
  settings: "key",
  outbox: "id, conversationId",
});

export { db };
