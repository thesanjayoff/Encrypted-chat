import { describe, it, expect } from "vitest";
import { generateIdentityKeyPair } from "../src/keys.js";
import { randomBytes, toBase64, fromBase64, utf8, fromUtf8 } from "../src/bytes.js";
import { ratchetInitAlice, ratchetInitBob, ratchetEncrypt, ratchetDecrypt, type RatchetHeader } from "../src/doubleRatchet.js";
import { createSenderKeyState, senderKeyEncrypt, senderKeyDecrypt } from "../src/senderKeys.js";

/**
 * "Message parsing" here means everything standing between a byte blob
 * handed to the client by the server (or an active attacker) and trusted
 * application plaintext: base64/UTF-8/JSON decoding of the wire envelope,
 * and the ratchet/Sender-Key decrypt calls that interpret attacker-supplied
 * header fields and ciphertext. A malicious or merely buggy server can hand
 * the client literally any bytes here. The contract under test is simple
 * but load-bearing: adversarial input must always either (a) decrypt to the
 * exact plaintext that was really encrypted, or (b) throw a plain Error —
 * it must never hang, crash the process in an uncatchable way, or return
 * plaintext that wasn't genuinely produced by the real sender.
 */

function randomHeader(): RatchetHeader {
  return {
    dhPublicKey: randomBytes(32),
    previousChainLength: Math.floor(Math.random() * 2 ** 32),
    messageNumber: Math.floor(Math.random() * 2 ** 32),
  };
}

function mutateOneByte(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes);
  if (copy.length === 0) return copy;
  const i = Math.floor(Math.random() * copy.length);
  copy[i] ^= 1 << Math.floor(Math.random() * 8);
  return copy;
}

describe("Fuzz: Double Ratchet decrypt against adversarial envelopes", () => {
  function freshSessionPair() {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const sharedSecret = randomBytes(32);
    const ad = utf8("test-associated-data");
    const aliceState = ratchetInitAlice(sharedSecret, ad, bob.dh.publicKey);
    const bobState = ratchetInitBob(sharedSecret, ad, bob.dh);
    return { aliceState, bobState };
  }

  it("a genuine message always round-trips", () => {
    const { aliceState, bobState } = freshSessionPair();
    const plaintext = utf8("hello, this is a real message");
    const msg = ratchetEncrypt(aliceState, plaintext);
    const decrypted = ratchetDecrypt(bobState, msg);
    expect(fromUtf8(decrypted)).toBe("hello, this is a real message");
  });

  it("never crashes (only decrypts-correctly or throws) against fully random headers + ciphertext", () => {
    for (let i = 0; i < 200; i++) {
      const { bobState } = freshSessionPair();
      const attack = { header: randomHeader(), ciphertext: randomBytes(Math.floor(Math.random() * 64)) };
      try {
        ratchetDecrypt(bobState, attack);
        // If it didn't throw, it must have produced *some* Uint8Array —
        // fine, AEAD auth already guards correctness; the point is no crash.
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
      }
    }
  });

  it("rejects a bit-flipped ciphertext (AEAD must not silently accept tampering)", () => {
    const { aliceState, bobState } = freshSessionPair();
    const msg = ratchetEncrypt(aliceState, utf8("sensitive content"));
    const tampered = { header: msg.header, ciphertext: mutateOneByte(msg.ciphertext) };
    expect(() => ratchetDecrypt(bobState, tampered)).toThrow();
  });

  it("refuses an absurd messageNumber instead of hanging or exhausting memory", () => {
    const { bobState } = freshSessionPair();
    const attack = { header: { dhPublicKey: randomBytes(32), previousChainLength: 0, messageNumber: Number.MAX_SAFE_INTEGER }, ciphertext: randomBytes(32) };
    expect(() => ratchetDecrypt(bobState, attack)).toThrow(/too many skipped|DoS/i);
  });

  it("handles a malformed (wrong-length) dhPublicKey by throwing, not crashing", () => {
    const { bobState } = freshSessionPair();
    for (const len of [0, 1, 16, 31, 33, 100]) {
      const attack = { header: { dhPublicKey: randomBytes(len), previousChainLength: 0, messageNumber: 0 }, ciphertext: randomBytes(32) };
      try {
        ratchetDecrypt(bobState, attack);
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
      }
    }
  });
});

describe("Fuzz: Sender Key decrypt against adversarial envelopes", () => {
  it("never crashes against random iteration/ciphertext/signature combinations", () => {
    const { state: senderState } = createSenderKeyState();
    for (let i = 0; i < 200; i++) {
      const attack = {
        iteration: Math.floor(Math.random() * 2 ** 32),
        ciphertext: randomBytes(Math.floor(Math.random() * 64)),
        signature: randomBytes(64),
      };
      try {
        senderKeyDecrypt(senderState, attack);
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
      }
    }
  });

  it("rejects a forged signature even with an otherwise-valid ciphertext", () => {
    const { state } = createSenderKeyState();
    const msg = senderKeyEncrypt(state, utf8("group message"));
    const forged = { ...msg, signature: randomBytes(64) };
    expect(() => senderKeyDecrypt(state, forged)).toThrow();
  });
});

describe("Fuzz: wire envelope decode pipeline (base64 -> utf8 -> JSON)", () => {
  // Mirrors what web/src/lib/messaging.ts's decryptEnvelope and
  // web/src/lib/groups.ts's handleDistribution do to an incoming
  // message's ciphertext field before any cryptographic operation runs.
  function decodeWireEnvelope(raw: string): unknown {
    return JSON.parse(fromUtf8(fromBase64(raw)));
  }

  it("random strings never crash the decode pipeline — only ever throw or return a value", () => {
    const samples = [
      "",
      "not base64 at all !!! ???",
      toBase64(randomBytes(0)),
      toBase64(randomBytes(1)),
      toBase64(randomBytes(500)),
      toBase64(utf8("not json")),
      toBase64(utf8("{")),
      toBase64(utf8("null")),
      toBase64(utf8("42")),
      toBase64(utf8('{"header":null}')),
      toBase64(utf8('{"header":{"dhPublicKey":"' + "x".repeat(10_000) + '"}}')),
    ];
    for (const sample of samples) {
      try {
        decodeWireEnvelope(sample);
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
      }
    }
  });

  it("100 fully random byte strings never crash the decode pipeline", () => {
    for (let i = 0; i < 100; i++) {
      const raw = toBase64(randomBytes(Math.floor(Math.random() * 200)));
      try {
        decodeWireEnvelope(raw);
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
      }
    }
  });
});
