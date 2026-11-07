import { x25519 } from "@noble/curves/ed25519.js";
import { hkdfExtract, hkdfExpand } from "./hkdf.js";
import { hmacSha256 } from "./hmac.js";
import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { concatBytes, fromHex, toHex, u32be, utf8, zeroize } from "./bytes.js";
import type { KeyPair } from "./keys.js";

/**
 * The Double Ratchet, following the published spec exactly:
 * https://signal.org/docs/specifications/doubleratchet/
 *
 * This implementation sends the ratchet header (sender's current DH public
 * key, previous chain length, message number) alongside the ciphertext in
 * plaintext — the "without header encryption" variant from the spec, not
 * Signal's Sesame-style sealed/encrypted-header variant. That means the
 * server (and any network observer) sees ratchet metadata — a message
 * counter and ephemeral DH public keys — but never plaintext or a long-term
 * key. Noted in THREAT_MODEL.md.
 */

const ROOT_KDF_INFO = utf8("E2EChat-DR-RootKey-v1");
const MSG_KDF_INFO = utf8("E2EChat-DR-MsgKeys-v1");
const CHAIN_KEY_CONST = new Uint8Array([0x02]);
const MESSAGE_KEY_CONST = new Uint8Array([0x01]);

const MAX_SKIP = 1000; // per-chain gap a single incoming message may force us to skip
const MAX_SKIPPED_KEYS = 2000; // total cached skipped-message keys (bounds memory under a flood)

export interface RatchetHeader {
  dhPublicKey: Uint8Array;
  previousChainLength: number;
  messageNumber: number;
}

export interface RatchetMessage {
  header: RatchetHeader;
  ciphertext: Uint8Array;
}

interface SkippedEntry {
  dhPublicKeyHex: string;
  messageNumber: number;
  messageKey: Uint8Array;
}

export class DoubleRatchetState {
  rootKey: Uint8Array;
  dhSelf: KeyPair;
  dhRemotePublicKey: Uint8Array | null;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendMessageNumber = 0;
  receiveMessageNumber = 0;
  previousSendingChainLength = 0;
  readonly associatedData: Uint8Array;
  skipped: Map<string, SkippedEntry> = new Map();

  constructor(params: {
    rootKey: Uint8Array;
    dhSelf: KeyPair;
    dhRemotePublicKey: Uint8Array | null;
    sendingChainKey: Uint8Array | null;
    receivingChainKey: Uint8Array | null;
    associatedData: Uint8Array;
  }) {
    this.rootKey = params.rootKey;
    this.dhSelf = params.dhSelf;
    this.dhRemotePublicKey = params.dhRemotePublicKey;
    this.sendingChainKey = params.sendingChainKey;
    this.receivingChainKey = params.receivingChainKey;
    this.associatedData = params.associatedData;
  }

  /** Serialize to a plain object for storage (e.g. encrypted local DB). */
  toJSON() {
    return {
      rootKey: toHex(this.rootKey),
      dhSelfPublicKey: toHex(this.dhSelf.publicKey),
      dhSelfPrivateKey: toHex(this.dhSelf.privateKey),
      dhRemotePublicKey: this.dhRemotePublicKey ? toHex(this.dhRemotePublicKey) : null,
      sendingChainKey: this.sendingChainKey ? toHex(this.sendingChainKey) : null,
      receivingChainKey: this.receivingChainKey ? toHex(this.receivingChainKey) : null,
      sendMessageNumber: this.sendMessageNumber,
      receiveMessageNumber: this.receiveMessageNumber,
      previousSendingChainLength: this.previousSendingChainLength,
      associatedData: toHex(this.associatedData),
      skipped: [...this.skipped.values()].map((e) => ({
        dhPublicKeyHex: e.dhPublicKeyHex,
        messageNumber: e.messageNumber,
        messageKey: toHex(e.messageKey),
      })),
    };
  }

  /** Reconstruct a state previously serialized with `.toJSON()` — e.g. after
   * loading it back out of an encrypted local database. */
  static fromJSON(json: ReturnType<DoubleRatchetState["toJSON"]>): DoubleRatchetState {
    const state = new DoubleRatchetState({
      rootKey: fromHex(json.rootKey),
      dhSelf: { publicKey: fromHex(json.dhSelfPublicKey), privateKey: fromHex(json.dhSelfPrivateKey) },
      dhRemotePublicKey: json.dhRemotePublicKey ? fromHex(json.dhRemotePublicKey) : null,
      sendingChainKey: json.sendingChainKey ? fromHex(json.sendingChainKey) : null,
      receivingChainKey: json.receivingChainKey ? fromHex(json.receivingChainKey) : null,
      associatedData: fromHex(json.associatedData),
    });
    state.sendMessageNumber = json.sendMessageNumber;
    state.receiveMessageNumber = json.receiveMessageNumber;
    state.previousSendingChainLength = json.previousSendingChainLength;
    for (const e of json.skipped) {
      state.skipped.set(`${e.dhPublicKeyHex}:${e.messageNumber}`, {
        dhPublicKeyHex: e.dhPublicKeyHex,
        messageNumber: e.messageNumber,
        messageKey: fromHex(e.messageKey),
      });
    }
    return state;
  }
}

function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

function generateDHKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/** KDF_RK: advance the root chain on a DH ratchet step. */
function kdfRootKey(rootKey: Uint8Array, dhOutput: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const prk = hkdfExtract(rootKey, dhOutput);
  const okm = hkdfExpand(prk, ROOT_KDF_INFO, 64);
  return { rootKey: okm.slice(0, 32), chainKey: okm.slice(32, 64) };
}

/** KDF_CK: advance a sending/receiving chain by one message. */
function kdfChainKey(chainKey: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
  return {
    messageKey: hmacSha256(chainKey, MESSAGE_KEY_CONST),
    chainKey: hmacSha256(chainKey, CHAIN_KEY_CONST),
  };
}

function encodeHeader(header: RatchetHeader): Uint8Array {
  return concatBytes(header.dhPublicKey, u32be(header.previousChainLength), u32be(header.messageNumber));
}

function messageEncrypt(messageKey: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  const okm = hkdfExpand(hkdfExtract(new Uint8Array(32), messageKey), MSG_KDF_INFO, 56);
  const aeadKey = okm.slice(0, 32);
  const nonce = okm.slice(32, 56);
  return aeadEncrypt(aeadKey, nonce, plaintext, ad);
}

function messageDecrypt(messageKey: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Uint8Array {
  const okm = hkdfExpand(hkdfExtract(new Uint8Array(32), messageKey), MSG_KDF_INFO, 56);
  const aeadKey = okm.slice(0, 32);
  const nonce = okm.slice(32, 56);
  return aeadDecrypt(aeadKey, nonce, ciphertext, ad);
}

/** Alice: she just ran X3DH and knows Bob's current ratchet public key
 * (his Signed PreKey public key, per spec section 3.3). */
export function ratchetInitAlice(
  sharedSecret: Uint8Array,
  associatedData: Uint8Array,
  bobRatchetPublicKey: Uint8Array,
): DoubleRatchetState {
  const dhSelf = generateDHKeyPair();
  const { rootKey, chainKey } = kdfRootKey(sharedSecret, dh(dhSelf.privateKey, bobRatchetPublicKey));
  return new DoubleRatchetState({
    rootKey,
    dhSelf,
    dhRemotePublicKey: bobRatchetPublicKey,
    sendingChainKey: chainKey,
    receivingChainKey: null,
    associatedData,
  });
}

/** Bob: his initial ratchet keypair is the Signed PreKey keypair he already
 * published (and used inside X3DH). */
export function ratchetInitBob(
  sharedSecret: Uint8Array,
  associatedData: Uint8Array,
  bobRatchetKeyPair: KeyPair,
): DoubleRatchetState {
  return new DoubleRatchetState({
    rootKey: sharedSecret,
    dhSelf: bobRatchetKeyPair,
    dhRemotePublicKey: null,
    sendingChainKey: null,
    receivingChainKey: null,
    associatedData,
  });
}

export function ratchetEncrypt(state: DoubleRatchetState, plaintext: Uint8Array): RatchetMessage {
  if (!state.sendingChainKey) {
    throw new Error("Cannot send yet: no sending chain established (waiting on the first inbound ratchet message)");
  }
  const { chainKey, messageKey } = kdfChainKey(state.sendingChainKey);
  state.sendingChainKey = chainKey;

  const header: RatchetHeader = {
    dhPublicKey: state.dhSelf.publicKey,
    previousChainLength: state.previousSendingChainLength,
    messageNumber: state.sendMessageNumber,
  };
  state.sendMessageNumber += 1;

  const ad = concatBytes(state.associatedData, encodeHeader(header));
  const ciphertext = messageEncrypt(messageKey, plaintext, ad);
  zeroize(messageKey);

  return { header, ciphertext };
}

function cacheSkipped(state: DoubleRatchetState, dhPublicKeyHex: string, n: number, key: Uint8Array) {
  const map = state.skipped;
  const mapKey = `${dhPublicKeyHex}:${n}`;
  map.set(mapKey, { dhPublicKeyHex, messageNumber: n, messageKey: key });
  if (map.size > MAX_SKIPPED_KEYS) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
}

function skipMessageKeys(state: DoubleRatchetState, until: number) {
  if (state.receiveMessageNumber + MAX_SKIP < until) {
    throw new Error("Too many skipped messages — refusing (possible DoS)");
  }
  if (!state.dhRemotePublicKey || !state.receivingChainKey) return;
  const dhHex = toHex(state.dhRemotePublicKey);
  while (state.receiveMessageNumber < until) {
    const { chainKey, messageKey } = kdfChainKey(state.receivingChainKey);
    cacheSkipped(state, dhHex, state.receiveMessageNumber, messageKey);
    state.receivingChainKey = chainKey;
    state.receiveMessageNumber += 1;
  }
}

function tryDecryptSkipped(state: DoubleRatchetState, header: RatchetHeader, ciphertext: Uint8Array, ad: Uint8Array): Uint8Array | null {
  const map = state.skipped;
  const mapKey = `${toHex(header.dhPublicKey)}:${header.messageNumber}`;
  const entry = map.get(mapKey);
  if (!entry) return null;
  map.delete(mapKey);
  const plaintext = messageDecrypt(entry.messageKey, ciphertext, ad);
  zeroize(entry.messageKey);
  return plaintext;
}

function dhRatchetStep(state: DoubleRatchetState, newRemotePublicKey: Uint8Array) {
  state.previousSendingChainLength = state.sendMessageNumber;
  state.sendMessageNumber = 0;
  state.receiveMessageNumber = 0;
  state.dhRemotePublicKey = newRemotePublicKey;

  const recv = kdfRootKey(state.rootKey, dh(state.dhSelf.privateKey, newRemotePublicKey));
  state.rootKey = recv.rootKey;
  state.receivingChainKey = recv.chainKey;

  const oldPrivate = state.dhSelf.privateKey;
  state.dhSelf = generateDHKeyPair();

  const send = kdfRootKey(state.rootKey, dh(state.dhSelf.privateKey, newRemotePublicKey));
  state.rootKey = send.rootKey;
  state.sendingChainKey = send.chainKey;

  zeroize(oldPrivate);
}

export function ratchetDecrypt(state: DoubleRatchetState, message: RatchetMessage): Uint8Array {
  const { header, ciphertext } = message;
  const ad = concatBytes(state.associatedData, encodeHeader(header));

  const skippedPlaintext = tryDecryptSkipped(state, header, ciphertext, ad);
  if (skippedPlaintext) return skippedPlaintext;

  const isNewRatchetKey = !state.dhRemotePublicKey || toHex(state.dhRemotePublicKey) !== toHex(header.dhPublicKey);
  if (isNewRatchetKey) {
    if (state.dhRemotePublicKey) {
      skipMessageKeys(state, header.previousChainLength);
    }
    dhRatchetStep(state, header.dhPublicKey);
  }

  skipMessageKeys(state, header.messageNumber);

  if (!state.receivingChainKey) throw new Error("No receiving chain established");
  const { chainKey, messageKey } = kdfChainKey(state.receivingChainKey);
  state.receivingChainKey = chainKey;
  state.receiveMessageNumber += 1;

  const plaintext = messageDecrypt(messageKey, ciphertext, ad);
  zeroize(messageKey);
  return plaintext;
}
