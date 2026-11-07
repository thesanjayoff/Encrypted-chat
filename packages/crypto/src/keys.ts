import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { randomBytes, utf8 } from "./bytes.js";

/**
 * Identity: deliberately two separate keypairs rather than one Ed25519 key
 * reused for X25519 DH via conversion (as XEdDSA does in real Signal). That
 * conversion is a well-known technique but it is one more piece of protocol
 * logic to get exactly right; using a plain Ed25519 key for signing and a
 * plain X25519 key for DH keeps every operation a direct, textbook use of a
 * vetted primitive with no conversion step to verify.
 */
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface IdentityKeyPair {
  signing: KeyPair; // Ed25519 — signs the Signed PreKey and Sender Key distributions
  dh: KeyPair; // X25519 — used directly in X3DH
}

export interface SignedPreKey {
  keyId: number;
  keyPair: KeyPair; // X25519
  signature: Uint8Array; // Ed25519 signature by the owning identity's signing key, over keyPair.publicKey
}

export interface OneTimePreKey {
  keyId: number;
  keyPair: KeyPair; // X25519
}

/** The public-only bundle a user publishes to the server / a peer fetches. */
export interface PreKeyBundle {
  identitySigningKey: Uint8Array;
  identityDhKey: Uint8Array;
  signedPreKeyId: number;
  signedPreKeyPublic: Uint8Array;
  signedPreKeySignature: Uint8Array;
  oneTimePreKeyId?: number;
  oneTimePreKeyPublic?: Uint8Array;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  const signingPrivate = ed25519.utils.randomSecretKey();
  const signingPublic = ed25519.getPublicKey(signingPrivate);
  const dhPrivate = x25519.utils.randomSecretKey();
  const dhPublic = x25519.getPublicKey(dhPrivate);
  return {
    signing: { publicKey: signingPublic, privateKey: signingPrivate },
    dh: { publicKey: dhPublic, privateKey: dhPrivate },
  };
}

function generateX25519KeyPair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/** Domain-separation prefix so a Signed PreKey signature can never be
 * replayed as, or confused with, a signature over any other kind of
 * identity-signed payload (e.g. a Sender Key distribution message). */
const SPK_SIGNATURE_CONTEXT = utf8("E2EChat-SignedPreKey-v1:");

export function generateSignedPreKey(
  identitySigningPrivateKey: Uint8Array,
  keyId: number,
): SignedPreKey {
  const keyPair = generateX25519KeyPair();
  const signature = ed25519.sign(
    concat(SPK_SIGNATURE_CONTEXT, keyPair.publicKey),
    identitySigningPrivateKey,
  );
  return { keyId, keyPair, signature };
}

export function verifySignedPreKey(
  identitySigningPublicKey: Uint8Array,
  signedPreKeyPublic: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(
      signature,
      concat(SPK_SIGNATURE_CONTEXT, signedPreKeyPublic),
      identitySigningPublicKey,
    );
  } catch {
    return false;
  }
}

export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKey[] {
  const out: OneTimePreKey[] = [];
  for (let i = 0; i < count; i++) {
    out.push({ keyId: startId + i, keyPair: generateX25519KeyPair() });
  }
  return out;
}

export function generateEphemeralKeyPair(): KeyPair {
  return generateX25519KeyPair();
}

/** Raw X25519 Diffie-Hellman, exposed for one-off handshakes outside X3DH
 * (device-linking's ephemeral key exchange — see web/src/lib/deviceLink.ts). */
export function x25519Dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

/** Recomputes an identity's public keys from its private halves — needed
 * when a device inherits an existing account's identity private keys over
 * the device-linking channel rather than generating its own. */
export function identityPublicKeysFrom(signingPrivateKey: Uint8Array, dhPrivateKey: Uint8Array): { signingPublicKey: Uint8Array; dhPublicKey: Uint8Array } {
  return { signingPublicKey: ed25519.getPublicKey(signingPrivateKey), dhPublicKey: x25519.getPublicKey(dhPrivateKey) };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export { randomBytes };
