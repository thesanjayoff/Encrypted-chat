import { computeSafetyNumber, formatSafetyNumber, fromBase64, type IdentityKeyPair } from "@e2e-chat/crypto";
import { db, type ContactRow } from "./db.js";
import { api } from "./api.js";
import { fetchDeviceBundles } from "./sessions.js";

/** Adds a contact server-side (an opaque id-pair the server uses only to
 * echo your own contact list back to you) and caches the account's
 * identity keys locally — needed both to compute a safety number right
 * away and to detect a later key change (someone re-registering, or a
 * compromised/malicious server attempting a key-substitution attack). */
export async function addContact(username: string, nickname?: string): Promise<ContactRow> {
  const added = await api.post<{ accountId: string; username: string }>("/api/contacts", { username });
  const bundles = await fetchDeviceBundles(username);
  if (bundles.length === 0) throw new Error(`${username} has no registered devices`);
  const [first] = bundles;

  const row: ContactRow = {
    accountId: added.accountId,
    username: added.username,
    nickname,
    addedAt: Date.now(),
    verified: false,
    identitySigningPublicKey: first.identitySigningKey,
    identityDhPublicKey: first.identityDhKey,
  };
  await db.contacts.put(row);
  return row;
}

export async function listContacts(): Promise<ContactRow[]> {
  return db.contacts.toArray();
}

export async function removeContact(accountId: string): Promise<void> {
  await api.del(`/api/contacts/${accountId}`);
  await db.contacts.delete(accountId);
  await db.deviceSessions.where("contactAccountId").equals(accountId).delete();
}

export async function setContactVerified(accountId: string, verified: boolean): Promise<void> {
  await db.contacts.update(accountId, { verified });
}

export function safetyNumberFor(selfIdentity: IdentityKeyPair, contact: ContactRow): string {
  const raw = computeSafetyNumber(
    { dhPublicKey: selfIdentity.dh.publicKey, signingPublicKey: selfIdentity.signing.publicKey },
    { dhPublicKey: fromBase64(contact.identityDhPublicKey), signingPublicKey: fromBase64(contact.identitySigningPublicKey) },
  );
  return formatSafetyNumber(raw);
}

/** Re-fetches a contact's current identity keys and reports whether they
 * changed since we last cached them — the "key change" warning the spec
 * calls for. Does NOT update the cache automatically; the caller should
 * only accept the new key after the user re-verifies, exactly like
 * Signal's "safety number has changed" flow. */
export async function checkForKeyChange(contact: ContactRow): Promise<{ changed: boolean; newSigningKey?: string; newDhKey?: string }> {
  // Note: like addContact, this consumes one of the contact's one-time
  // prekeys just to read their (unchanging, in the common case) identity
  // keys — an accepted inefficiency here in favor of not adding a
  // separate "identity keys only" server endpoint for this learning project.
  const bundles = await fetchDeviceBundles(contact.username);
  const [first] = bundles;
  if (!first) return { changed: false };
  const changed = first.identitySigningKey !== contact.identitySigningPublicKey || first.identityDhKey !== contact.identityDhPublicKey;
  return changed ? { changed, newSigningKey: first.identitySigningKey, newDhKey: first.identityDhKey } : { changed: false };
}

export async function acceptKeyChange(accountId: string, newSigningKey: string, newDhKey: string): Promise<void> {
  await db.contacts.update(accountId, { identitySigningPublicKey: newSigningKey, identityDhPublicKey: newDhKey, verified: false });
  await db.deviceSessions.where("contactAccountId").equals(accountId).delete();
}
