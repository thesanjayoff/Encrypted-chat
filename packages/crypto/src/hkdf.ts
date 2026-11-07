import { hkdf as nobleHkdf, extract, expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/** HKDF-Extract, RFC 5869 section 2.2, fixed to SHA-256. */
export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return extract(sha256, ikm, salt);
}

/** HKDF-Expand, RFC 5869 section 2.3, fixed to SHA-256. */
export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return expand(sha256, prk, info, length);
}

/** Full HKDF-SHA256 (extract-then-expand), RFC 5869. */
export function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return nobleHkdf(sha256, ikm, salt, info, length);
}
