import { argon2idAsync } from "@noble/hashes/argon2.js";
import { aeadEncrypt, aeadDecrypt, randomBytes, concatBytes, utf8, fromUtf8, toBase64, fromBase64, zeroize } from "@e2e-chat/crypto";

/**
 * Local storage encryption. Every sensitive row this app writes to
 * IndexedDB (private keys, Double Ratchet / Sender Key session state,
 * decrypted message text cached for display) is sealed with this vault's
 * key before it touches disk — never store the plaintext, never store it
 * unencrypted "just this once."
 *
 * Two modes, both real, with an honest tradeoff:
 * - App Lock ON: the key is derived from the user's passcode via Argon2id
 *   (OWASP-recommended parameters). The passcode never touches disk; only
 *   a salt and a small verifier blob do. Losing the passcode means losing
 *   the data — there is no recovery, by design.
 * - App Lock OFF (default, for a frictionless first run): a random key is
 *   generated once and stored directly in IndexedDB. This is NOT real
 *   protection against anything that can read this origin's IndexedDB (a
 *   compromised browser, device malware, or physical access to an
 *   unlocked device) — it only keeps the data out of, e.g., a casual
 *   backup/sync of the raw database file. The UI should nudge users
 *   toward turning App Lock on.
 */

const ARGON2_PARAMS = { t: 2, m: 19456, p: 1, dkLen: 32 }; // OWASP-minimum Argon2id params
const VERIFIER_PLAINTEXT = utf8("e2e-chat-vault-verifier-v1");
const META_DB = "e2e-chat-vault-meta";
const META_STORE = "meta";

interface VaultMeta {
  hasPasscode: boolean;
  salt?: string; // base64, only if hasPasscode
  verifier?: string; // base64 nonce||ciphertext, only if hasPasscode
  rawKey?: string; // base64, only if !hasPasscode
}

function openMetaDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(META_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(META_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function getMeta(): Promise<VaultMeta | undefined> {
  const db = await openMetaDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, "readonly");
    const req = tx.objectStore(META_STORE).get("meta");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function setMeta(meta: VaultMeta): Promise<void> {
  const db = await openMetaDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, "readwrite");
    tx.objectStore(META_STORE).put(meta, "meta");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

class Vault {
  private key: Uint8Array | null = null;

  get isUnlocked(): boolean {
    return this.key !== null;
  }

  async hasPasscode(): Promise<boolean> {
    const meta = await getMeta();
    return meta?.hasPasscode ?? false;
  }

  async isInitialized(): Promise<boolean> {
    return (await getMeta()) !== undefined;
  }

  /** First-run setup: call exactly once, before any identity/session data exists. */
  async initialize(passcode: string | null): Promise<void> {
    if (passcode) {
      const salt = randomBytes(16);
      const key = await argon2idAsync(utf8(passcode), salt, ARGON2_PARAMS);
      const nonce = randomBytes(24);
      const verifier = aeadEncrypt(key, nonce, VERIFIER_PLAINTEXT);
      await setMeta({ hasPasscode: true, salt: toBase64(salt), verifier: toBase64(concatBytes(nonce, verifier)) });
      this.key = key;
    } else {
      const key = randomBytes(32);
      await setMeta({ hasPasscode: false, rawKey: toBase64(key) });
      this.key = key;
    }
  }

  /** Call on app load. Returns true if unlocked without needing a passcode prompt. */
  async tryAutoUnlock(): Promise<boolean> {
    const meta = await getMeta();
    if (!meta) return false;
    if (!meta.hasPasscode && meta.rawKey) {
      this.key = fromBase64(meta.rawKey);
      return true;
    }
    return false;
  }

  async unlockWithPasscode(passcode: string): Promise<boolean> {
    const meta = await getMeta();
    if (!meta?.hasPasscode || !meta.salt || !meta.verifier) return false;
    const salt = fromBase64(meta.salt);
    const key = await argon2idAsync(utf8(passcode), salt, ARGON2_PARAMS);
    const blob = fromBase64(meta.verifier);
    try {
      const plaintext = aeadDecrypt(key, blob.slice(0, 24), blob.slice(24));
      if (fromUtf8(plaintext) !== fromUtf8(VERIFIER_PLAINTEXT)) return false;
    } catch {
      return false;
    }
    this.key = key;
    return true;
  }

  lock(): void {
    if (this.key) zeroize(this.key);
    this.key = null;
  }

  encryptBytes(plaintext: Uint8Array): string {
    if (!this.key) throw new Error("vault is locked");
    const nonce = randomBytes(24);
    const ciphertext = aeadEncrypt(this.key, nonce, plaintext);
    return toBase64(concatBytes(nonce, ciphertext));
  }

  decryptBytes(blobB64: string): Uint8Array {
    if (!this.key) throw new Error("vault is locked");
    const blob = fromBase64(blobB64);
    return aeadDecrypt(this.key, blob.slice(0, 24), blob.slice(24));
  }

  encryptJSON(value: unknown): string {
    return this.encryptBytes(utf8(JSON.stringify(value)));
  }

  decryptJSON<T>(blobB64: string): T {
    return JSON.parse(fromUtf8(this.decryptBytes(blobB64))) as T;
  }
}

export const vault = new Vault();
