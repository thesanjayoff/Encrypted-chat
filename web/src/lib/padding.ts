import { concatBytes, u32be } from "@e2e-chat/crypto";

/**
 * Pads plaintext to the next size bucket before encryption, so the server
 * (and any network observer) sees only a handful of ciphertext lengths
 * instead of one length per message — "pad message sizes" per the spec.
 * Buckets grow geometrically; anything past the largest bucket rounds up
 * to the next 16KiB multiple instead (keeps attachments-as-text-ish blobs
 * from blowing past a fixed ceiling).
 */
const BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384];

function bucketFor(len: number): number {
  for (const b of BUCKETS) if (len <= b) return b;
  const last = BUCKETS[BUCKETS.length - 1];
  return Math.ceil(len / last) * last;
}

export function padMessage(plaintext: Uint8Array): Uint8Array {
  const bucket = bucketFor(plaintext.length + 4);
  const padded = new Uint8Array(bucket);
  padded.set(u32be(plaintext.length), 0);
  padded.set(plaintext, 4);
  return padded;
}

export function unpadMessage(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) throw new Error("padded message too short");
  const len = ((padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3]) >>> 0;
  if (len < 0 || len + 4 > padded.length) throw new Error("corrupt padding length");
  return padded.slice(4, 4 + len);
}
