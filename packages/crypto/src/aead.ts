import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

export const AEAD_KEY_BYTES = 32;
export const AEAD_NONCE_BYTES = 24;

/** Authenticated encryption used everywhere a derived message/file key needs
 * to protect data: XChaCha20-Poly1305 (24-byte nonce — safe to pick at
 * random, no risk of the nonce-reuse that plagues 12-byte ChaCha20/AES-GCM
 * nonces derived from counters across restarts). */
export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(key, nonce, associatedData).encrypt(plaintext);
}

export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData?: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(key, nonce, associatedData).decrypt(ciphertext);
}
