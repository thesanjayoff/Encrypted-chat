import { randomBytes as nobleRandomBytes, utf8ToBytes, bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { equalBytes } from "@noble/ciphers/utils.js";
import { base64 } from "@scure/base";

export { concatBytes } from "@noble/hashes/utils.js";

export function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

export function u8(n: number): Uint8Array {
  return new Uint8Array([n & 0xff]);
}

/** Constant-time equality (noble's `equalBytes` is designed for secret
 * comparisons). Never use === on secret byte arrays or MAC/tag values. */
export const constantTimeEqual = equalBytes;

/** Best-effort zeroing of key material. JS cannot guarantee the memory is
 * wiped (the GC may have already copied the buffer), but this drops the
 * reference we control the moment a key is no longer needed. */
export function zeroize(buf: Uint8Array | null | undefined): void {
  if (buf) buf.fill(0);
}

export const toHex = bytesToHex;
export const fromHex = hexToBytes;
export const toBase64 = (b: Uint8Array): string => base64.encode(b);
export const fromBase64 = (s: string): Uint8Array => base64.decode(s);
export const utf8 = utf8ToBytes;
export { bytesToUtf8 as fromUtf8 } from "@noble/ciphers/utils.js";

export function randomBytes(n: number): Uint8Array {
  return nobleRandomBytes(n);
}
