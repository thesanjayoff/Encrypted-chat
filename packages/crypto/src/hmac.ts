import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** HMAC-SHA256 per RFC 2104, from the audited `@noble/hashes` primitive. */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export const HMAC_SHA256_OUTPUT_BYTES = 32;
