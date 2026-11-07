import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdfExtract, hkdfExpand } from "./hkdf.js";
import { hmacSha256 } from "./hmac.js";
import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { concatBytes, randomBytes, toHex, u32be, utf8, zeroize } from "./bytes.js";
import type { KeyPair } from "./keys.js";

/**
 * Sender Keys for group messaging — Signal's approach (not MLS): each
 * member distributes one symmetric "chain key" plus a dedicated Ed25519
 * signing keypair to every other member, 1:1, over their already-verified
 * Double Ratchet session. Every group message is then symmetric-chain
 * encrypted (fast — one encrypt reaches every recipient) *and* signed with
 * that per-sender signing key, so that no other member — despite also
 * holding the shared chain key — can forge a message that appears to come
 * from this sender.
 *
 * Removing a member: the sender must rotate (generate a brand-new chain key
 * + signing keypair) and redistribute only to the members who remain. The
 * removed member keeps the old chain key, which only ever advances forward
 * and is never reused for a new epoch, so they cannot decrypt anything sent
 * after the rotation. That policy is enforced by the application layer
 * (server/web client), not by this module — see server/src/groups.ts.
 */

const MSG_KDF_INFO = utf8("E2EChat-SenderKey-MsgKeys-v1");
const SIGNATURE_CONTEXT = utf8("E2EChat-SenderKey-Sig-v1:");
const CHAIN_KEY_CONST = new Uint8Array([0x02]);
const MESSAGE_KEY_CONST = new Uint8Array([0x01]);

const MAX_SKIP = 1000;
const MAX_SKIPPED_KEYS = 2000;

export interface SenderKeyDistribution {
  chainKey: Uint8Array;
  signingPublicKey: Uint8Array;
  iteration: number;
}

export class SenderKeyState {
  chainKey: Uint8Array;
  signingKeyPair: KeyPair | null; // null for a state built from a received distribution (no private signing key)
  signingPublicKey: Uint8Array;
  iteration: number;
  skipped: Map<number, Uint8Array> = new Map();

  constructor(chainKey: Uint8Array, signingPublicKey: Uint8Array, iteration: number, signingKeyPair: KeyPair | null) {
    this.chainKey = chainKey;
    this.signingPublicKey = signingPublicKey;
    this.iteration = iteration;
    this.signingKeyPair = signingKeyPair;
  }
}

function kdfChainKey(chainKey: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  return {
    messageKey: hmacSha256(chainKey, MESSAGE_KEY_CONST),
    chainKey: hmacSha256(chainKey, CHAIN_KEY_CONST),
  };
}

function deriveAead(messageKey: Uint8Array): { aeadKey: Uint8Array; nonce: Uint8Array } {
  const okm = hkdfExpand(hkdfExtract(new Uint8Array(32), messageKey), MSG_KDF_INFO, 56);
  return { aeadKey: okm.slice(0, 32), nonce: okm.slice(32, 56) };
}

/** Create a brand-new Sender Key for this user in this group (initial join,
 * or a rotation after a membership change). Only the creator keeps the
 * private signing key; what gets distributed to other members is `.distribution`. */
export function createSenderKeyState(): { state: SenderKeyState; distribution: SenderKeyDistribution } {
  const chainKey = randomBytes(32);
  const signingPrivateKey = ed25519.utils.randomSecretKey();
  const signingPublicKey = ed25519.getPublicKey(signingPrivateKey);
  const state = new SenderKeyState(chainKey, signingPublicKey, 0, {
    publicKey: signingPublicKey,
    privateKey: signingPrivateKey,
  });
  return { state, distribution: { chainKey, signingPublicKey, iteration: 0 } };
}

/** A recipient builds their local copy of a sender's state from the
 * distribution message they received over that sender's 1:1 session. */
export function receiveSenderKeyDistribution(distribution: SenderKeyDistribution): SenderKeyState {
  return new SenderKeyState(distribution.chainKey.slice(), distribution.signingPublicKey, distribution.iteration, null);
}

export interface SenderKeyMessage {
  iteration: number;
  ciphertext: Uint8Array;
  signature: Uint8Array;
}

export function senderKeyEncrypt(state: SenderKeyState, plaintext: Uint8Array, associatedData?: Uint8Array): SenderKeyMessage {
  if (!state.signingKeyPair) throw new Error("Cannot encrypt with a state built from a received distribution (no private signing key)");

  const { chainKey, messageKey } = kdfChainKey(state.chainKey);
  state.chainKey = chainKey;
  const iteration = state.iteration;
  state.iteration += 1;

  const { aeadKey, nonce } = deriveAead(messageKey);
  const ciphertext = aeadEncrypt(aeadKey, nonce, plaintext, associatedData);
  zeroize(messageKey);

  const signature = ed25519.sign(concatBytes(SIGNATURE_CONTEXT, u32be(iteration), ciphertext), state.signingKeyPair.privateKey);

  return { iteration, ciphertext, signature };
}

function cacheSkipped(state: SenderKeyState, iteration: number, key: Uint8Array) {
  state.skipped.set(iteration, key);
  if (state.skipped.size > MAX_SKIPPED_KEYS) {
    const oldest = state.skipped.keys().next().value;
    if (oldest !== undefined) state.skipped.delete(oldest);
  }
}

function skipTo(state: SenderKeyState, until: number) {
  if (state.iteration + MAX_SKIP < until) {
    throw new Error("Too many skipped group messages — refusing (possible DoS)");
  }
  while (state.iteration < until) {
    const { chainKey, messageKey } = kdfChainKey(state.chainKey);
    cacheSkipped(state, state.iteration, messageKey);
    state.chainKey = chainKey;
    state.iteration += 1;
  }
}

export function senderKeyDecrypt(state: SenderKeyState, message: SenderKeyMessage, associatedData?: Uint8Array): Uint8Array {
  const signed = concatBytes(SIGNATURE_CONTEXT, u32be(message.iteration), message.ciphertext);
  if (!ed25519.verify(message.signature, signed, state.signingPublicKey)) {
    throw new Error("Sender Key signature verification failed — message rejected");
  }

  let messageKey: Uint8Array;
  if (state.skipped.has(message.iteration)) {
    messageKey = state.skipped.get(message.iteration)!;
    state.skipped.delete(message.iteration);
  } else if (message.iteration === state.iteration) {
    const advanced = kdfChainKey(state.chainKey);
    state.chainKey = advanced.chainKey;
    state.iteration += 1;
    messageKey = advanced.messageKey;
  } else if (message.iteration > state.iteration) {
    skipTo(state, message.iteration);
    const advanced = kdfChainKey(state.chainKey);
    state.chainKey = advanced.chainKey;
    state.iteration += 1;
    messageKey = advanced.messageKey;
  } else {
    throw new Error("Message key for this iteration was already consumed or never cached (stale/replayed message)");
  }

  const { aeadKey, nonce } = deriveAead(messageKey);
  const plaintext = aeadDecrypt(aeadKey, nonce, message.ciphertext, associatedData);
  zeroize(messageKey);
  return plaintext;
}

export const senderKeyStateFingerprint = (state: SenderKeyState): string => toHex(state.signingPublicKey);
