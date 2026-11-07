import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "./hkdf.js";
import { concatBytes, utf8, zeroize } from "./bytes.js";
import { verifySignedPreKey, type IdentityKeyPair, type KeyPair, type OneTimePreKey, type PreKeyBundle, type SignedPreKey } from "./keys.js";

/**
 * X3DH key agreement, following the published spec exactly:
 * https://signal.org/docs/specifications/x3dh/
 *
 * DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)
 * DH3 = DH(EK_A, SPK_B)   DH4 = DH(EK_A, OPK_B)   (DH4 only if an OPK was available)
 * SK  = HKDF(F || DH1 || DH2 || DH3 || DH4)
 *
 * F is 32 0xFF bytes, prepended per spec section 3.3 so that, in curves
 * (like X25519) where a small-order/invalid point could otherwise be
 * confused with a valid low-value scalar multiplication result, the KDF
 * input space for a real exchange can never collide with a degenerate one.
 */

const X3DH_INFO = utf8("E2EChat-X3DH-v1");
const ZERO_SALT = new Uint8Array(32);
const F_PREFIX = new Uint8Array(32).fill(0xff);

function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

export interface X3DHResult {
  sharedSecret: Uint8Array; // 32 bytes — feed directly into Double Ratchet RatchetInit
  associatedData: Uint8Array; // IK_initiator || IK_responder, bind to every ratchet AEAD call
}

export class X3DHVerificationError extends Error {
  constructor(message = "Signed PreKey signature did not verify") {
    super(message);
  }
}

/** Alice's side: she has Bob's published bundle and wants to start a session. */
export function x3dhInitiate(
  initiatorIdentity: IdentityKeyPair,
  responderBundle: PreKeyBundle,
): X3DHResult & { ephemeralKeyPair: KeyPair } {
  const sigOk = verifySignedPreKey(
    responderBundle.identitySigningKey,
    responderBundle.signedPreKeyPublic,
    responderBundle.signedPreKeySignature,
  );
  if (!sigOk) throw new X3DHVerificationError();

  const ephemeralPrivate = x25519.utils.randomSecretKey();
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);

  const dh1 = dh(initiatorIdentity.dh.privateKey, responderBundle.signedPreKeyPublic);
  const dh2 = dh(ephemeralPrivate, responderBundle.identityDhKey);
  const dh3 = dh(ephemeralPrivate, responderBundle.signedPreKeyPublic);
  const dh4 = responderBundle.oneTimePreKeyPublic
    ? dh(ephemeralPrivate, responderBundle.oneTimePreKeyPublic)
    : new Uint8Array(0);

  const ikm = concatBytes(F_PREFIX, dh1, dh2, dh3, dh4);
  const sharedSecret = hkdf(ikm, ZERO_SALT, X3DH_INFO, 32);

  zeroize(dh1);
  zeroize(dh2);
  zeroize(dh3);
  zeroize(dh4);
  zeroize(ikm);

  const associatedData = concatBytes(initiatorIdentity.dh.publicKey, responderBundle.identityDhKey);

  return {
    sharedSecret,
    associatedData,
    ephemeralKeyPair: { publicKey: ephemeralPublic, privateKey: ephemeralPrivate },
  };
}

/** Bob's side: he receives Alice's identity key + the ephemeral key she used,
 * and which of his own SPK/OPK ids she used, and recomputes the same secret. */
export function x3dhRespond(
  responderIdentity: IdentityKeyPair,
  responderSignedPreKey: SignedPreKey,
  responderOneTimePreKey: OneTimePreKey | undefined,
  initiatorIdentityDhPublic: Uint8Array,
  initiatorEphemeralPublic: Uint8Array,
): X3DHResult {
  const dh1 = dh(responderSignedPreKey.keyPair.privateKey, initiatorIdentityDhPublic);
  const dh2 = dh(responderIdentity.dh.privateKey, initiatorEphemeralPublic);
  const dh3 = dh(responderSignedPreKey.keyPair.privateKey, initiatorEphemeralPublic);
  const dh4 = responderOneTimePreKey
    ? dh(responderOneTimePreKey.keyPair.privateKey, initiatorEphemeralPublic)
    : new Uint8Array(0);

  const ikm = concatBytes(F_PREFIX, dh1, dh2, dh3, dh4);
  const sharedSecret = hkdf(ikm, ZERO_SALT, X3DH_INFO, 32);

  zeroize(dh1);
  zeroize(dh2);
  zeroize(dh3);
  zeroize(dh4);
  zeroize(ikm);

  const associatedData = concatBytes(initiatorIdentityDhPublic, responderIdentity.dh.publicKey);

  return { sharedSecret, associatedData };
}
