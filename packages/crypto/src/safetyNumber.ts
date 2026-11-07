import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes, u32be } from "./bytes.js";

/**
 * Safety numbers (a.k.a. "fingerprint" / key verification), inspired by
 * Signal's numeric fingerprint but not byte-for-byte identical to it: we
 * iterate a vetted hash (BLAKE2b, from @noble/hashes) many times over a
 * version byte + the identity's public DH key + public signing key, then
 * render the digest as decimal digits grouped for easy reading/typing, and
 * combine both parties' fingerprints in a fixed (sorted) order so both
 * sides compute the exact same combined safety number regardless of who
 * opens the verification screen first.
 */

const VERSION = 1;
const ITERATIONS = 5200; // mirrors Signal's iteration count; raises the cost of any hash-based shortcut
const FINGERPRINT_BYTES = 30; // -> 5 groups of 6 decimal digits = 30 digits, Signal-style

function iteratedHash(identityDhKey: Uint8Array, identitySigningKey: Uint8Array): Uint8Array {
  let digest = concatBytes(u32be(VERSION), identityDhKey, identitySigningKey);
  for (let i = 0; i < ITERATIONS; i++) {
    digest = blake2b(concatBytes(digest, identityDhKey), { dkLen: 32 });
  }
  return digest.slice(0, FINGERPRINT_BYTES);
}

/** Render a 30-byte digest as 5 groups of 6 decimal digits (30 digits total). */
function toDecimalGroups(bytes: Uint8Array): string {
  let groups = "";
  for (let g = 0; g < 5; g++) {
    // Each group consumes 6 bytes and renders as a 6-byte big-endian value
    // reduced mod 10^6 is INSUFFICIENT entropy mapping on its own, so instead
    // we treat each 6-byte chunk as a big integer and take it mod 10^6 — fine
    // for a human-comparison fingerprint (not itself a secret key).
    const chunk = bytes.slice(g * 6, g * 6 + 6);
    let value = 0n;
    for (const byte of chunk) value = (value << 8n) | BigInt(byte);
    const digits = (value % 1_000_000n).toString().padStart(6, "0");
    groups += digits;
  }
  return groups;
}

export interface IdentityForFingerprint {
  dhPublicKey: Uint8Array;
  signingPublicKey: Uint8Array;
}

/** A single party's fingerprint (what Signal calls their "numeric fingerprint"). */
export function computeFingerprint(identity: IdentityForFingerprint): string {
  return toDecimalGroups(iteratedHash(identity.dhPublicKey, identity.signingPublicKey));
}

/** The combined safety number both users compare. Order-independent: it
 * sorts the two fingerprints so Alice and Bob — regardless of who is
 * "local" vs. "remote" on each device — render the identical string. */
export function computeSafetyNumber(a: IdentityForFingerprint, b: IdentityForFingerprint): string {
  const fa = computeFingerprint(a);
  const fb = computeFingerprint(b);
  return fa <= fb ? fa + fb : fb + fa;
}

/** Group safety numbers into blocks of 5 digits for display, Signal-style. */
export function formatSafetyNumber(safetyNumber: string): string {
  const blocks: string[] = [];
  for (let i = 0; i < safetyNumber.length; i += 5) {
    blocks.push(safetyNumber.slice(i, i + 5));
  }
  return blocks.join(" ");
}
