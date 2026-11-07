import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { DB_PATH, ATTACHMENTS_DIR } from "./env.js";

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
fs.mkdirSync(ATTACHMENTS_DIR, { recursive: true });

const raw = new DatabaseSync(DB_PATH);
raw.exec("PRAGMA journal_mode = WAL");
raw.exec("PRAGMA foreign_keys = ON");

interface LooseStatement {
  run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
  get(...params: unknown[]): any;
  all(...params: unknown[]): any[];
}

/** node:sqlite returns BLOB columns as plain Uint8Array, not Buffer (unlike
 * better-sqlite3). Route code throughout this server calls Buffer-only
 * methods (`.toString('base64')`, `.equals()`) on values read back from the
 * DB, so convert every BLOB field to a real Buffer right at the boundary —
 * one fix here instead of a `Buffer.from(...)` at every call site. */
function toBuffers<T>(row: T): T {
  if (row == null || typeof row !== "object") return row;
  for (const key of Object.keys(row as object)) {
    const value = (row as Record<string, unknown>)[key];
    if (value instanceof Uint8Array && !Buffer.isBuffer(value)) {
      (row as Record<string, unknown>)[key] = Buffer.from(value);
    }
  }
  return row;
}

/** Thin shim so route code can keep the familiar `db.transaction(fn)()`
 * ergonomics on top of node's built-in `node:sqlite` (no native build step
 * — unlike better-sqlite3, which requires a C++ toolchain this environment
 * doesn't have installed). Statement results are typed loosely (`any`,
 * matching better-sqlite3's own types) because every row shape here is
 * already declared per-query at the call site via `as SomeRowType`. */
export const db = {
  prepare: (sql: string): LooseStatement => {
    const stmt = raw.prepare(sql);
    return {
      run: stmt.run.bind(stmt) as LooseStatement["run"],
      get: (...params: unknown[]) => toBuffers(stmt.get(...(params as any))),
      all: (...params: unknown[]) => (stmt.all(...(params as any)) as unknown[]).map(toBuffers),
    };
  },
  exec: raw.exec.bind(raw),
  transaction<T extends (...args: never[]) => unknown>(fn: T): (...args: Parameters<T>) => ReturnType<T> {
    return (...args: Parameters<T>): ReturnType<T> => {
      raw.exec("BEGIN");
      try {
        const result = fn(...args) as ReturnType<T>;
        raw.exec("COMMIT");
        return result;
      } catch (err) {
        raw.exec("ROLLBACK");
        throw err;
      }
    };
  },
};

/**
 * Schema notes (see THREAT_MODEL.md for the full rationale):
 * - No column here ever holds plaintext message content or a private key.
 * - `ciphertext` columns are opaque blobs as far as this server is concerned.
 * - Sealed-sender messages have NULL from_account_id/from_device_id: the
 *   server genuinely does not know who sent them, only who to deliver to.
 * - Everything with an `expires_at` is swept by server/src/retention.ts.
 */
db.exec(`
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  opaque_registration_record TEXT NOT NULL,
  identity_signing_public_key BLOB NOT NULL,
  identity_dh_public_key BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  label TEXT,
  is_primary INTEGER NOT NULL DEFAULT 0,
  signed_prekey_id INTEGER NOT NULL,
  signed_prekey_public BLOB NOT NULL,
  signed_prekey_signature BLOB NOT NULL,
  signed_prekey_created_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_id);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  public_key BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (device_id, key_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS pending_logins (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  opaque_state BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
  owner_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  contact_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner_account_id, contact_account_id)
);

CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  created_by_account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  added_at INTEGER NOT NULL,
  PRIMARY KEY (group_id, account_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  to_account_id TEXT NOT NULL,
  to_device_id TEXT NOT NULL,
  from_account_id TEXT,
  from_device_id TEXT,
  envelope_type TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(to_account_id, to_device_id);
CREATE INDEX IF NOT EXISTS idx_messages_expiry ON messages(expires_at);

CREATE TABLE IF NOT EXISTS recent_message_hashes (
  hash TEXT PRIMARY KEY,
  to_device_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,
  owner_account_id TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_link_sessions (
  token TEXT PRIMARY KEY,
  primary_account_id TEXT NOT NULL,
  primary_device_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
`);
