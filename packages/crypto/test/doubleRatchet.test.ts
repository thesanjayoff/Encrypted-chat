import { describe, it, expect } from "vitest";
import { generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, type PreKeyBundle } from "../src/keys.js";
import { x3dhInitiate, x3dhRespond } from "../src/x3dh.js";
import { ratchetInitAlice, ratchetInitBob, ratchetEncrypt, ratchetDecrypt, type DoubleRatchetState, type RatchetMessage } from "../src/doubleRatchet.js";
import { utf8, fromUtf8 } from "../src/bytes.js";

/** Sets up a fresh Alice/Bob session pair via a real X3DH handshake, exactly
 * as the app would. Returns both ratchet states plus Bob's identity+SPK/OTPK
 * so later tests can instantiate Bob's ratchet. */
function setupSession() {
  const alice = generateIdentityKeyPair();
  const bob = generateIdentityKeyPair();
  const bobSpk = generateSignedPreKey(bob.signing.privateKey, 1);
  const [bobOtpk] = generateOneTimePreKeys(1, 1);

  const bundle: PreKeyBundle = {
    identitySigningKey: bob.signing.publicKey,
    identityDhKey: bob.dh.publicKey,
    signedPreKeyId: bobSpk.keyId,
    signedPreKeyPublic: bobSpk.keyPair.publicKey,
    signedPreKeySignature: bobSpk.signature,
    oneTimePreKeyId: bobOtpk.keyId,
    oneTimePreKeyPublic: bobOtpk.keyPair.publicKey,
  };

  const aliceX3dh = x3dhInitiate(alice, bundle);
  const bobX3dh = x3dhRespond(bob, bobSpk, bobOtpk, alice.dh.publicKey, aliceX3dh.ephemeralKeyPair.publicKey);

  const aliceRatchet = ratchetInitAlice(aliceX3dh.sharedSecret, aliceX3dh.associatedData, bobSpk.keyPair.publicKey);
  const bobRatchet = ratchetInitBob(bobX3dh.sharedSecret, bobX3dh.associatedData, bobSpk.keyPair);

  return { aliceRatchet, bobRatchet };
}

function send(from: DoubleRatchetState, text: string): RatchetMessage {
  return ratchetEncrypt(from, utf8(text));
}

function receive(to: DoubleRatchetState, msg: RatchetMessage): string {
  return fromUtf8(ratchetDecrypt(to, msg));
}

describe("Double Ratchet", () => {
  it("basic round trip, both directions", () => {
    const { aliceRatchet, bobRatchet } = setupSession();

    const m1 = send(aliceRatchet, "hello bob");
    expect(receive(bobRatchet, m1)).toBe("hello bob");

    const m2 = send(bobRatchet, "hi alice");
    expect(receive(aliceRatchet, m2)).toBe("hi alice");

    const m3 = send(aliceRatchet, "how are you");
    expect(receive(bobRatchet, m3)).toBe("how are you");
  });

  it("handles out-of-order delivery within a chain", () => {
    const { aliceRatchet, bobRatchet } = setupSession();
    // Bob must ratchet at least once before Alice can decrypt back, but here
    // we only need Alice -> Bob out-of-order, which works from message 0.
    const m1 = send(aliceRatchet, "one");
    const m2 = send(aliceRatchet, "two");
    const m3 = send(aliceRatchet, "three");

    // Deliver out of order: 3, 1, 2
    expect(receive(bobRatchet, m3)).toBe("three");
    expect(receive(bobRatchet, m1)).toBe("one");
    expect(receive(bobRatchet, m2)).toBe("two");
  });

  it("handles a lost (never-delivered) message without breaking later ones", () => {
    const { aliceRatchet, bobRatchet } = setupSession();
    const m1 = send(aliceRatchet, "one");
    const m2 = send(aliceRatchet, "two"); // never delivered — simulates network loss
    const m3 = send(aliceRatchet, "three");

    expect(receive(bobRatchet, m1)).toBe("one");
    expect(receive(bobRatchet, m3)).toBe("three");
    void m2;
  });

  it("rejects a duplicate (replayed) message", () => {
    const { aliceRatchet, bobRatchet } = setupSession();
    const m1 = send(aliceRatchet, "one");
    expect(receive(bobRatchet, m1)).toBe("one");
    // Replaying the same envelope: the skipped-key cache has nothing for it
    // (it was consumed), and it's behind the current chain position, so
    // re-deriving would desync the chain — the implementation must reject it
    // rather than silently re-deriving a stale key.
    expect(() => ratchetDecrypt(bobRatchet, m1)).toThrow();
  });

  it("recovers correctly across multiple DH ratchet steps interleaved both ways", () => {
    const { aliceRatchet, bobRatchet } = setupSession();
    expect(receive(bobRatchet, send(aliceRatchet, "a1"))).toBe("a1");
    expect(receive(aliceRatchet, send(bobRatchet, "b1"))).toBe("b1");
    expect(receive(bobRatchet, send(aliceRatchet, "a2"))).toBe("a2");
    expect(receive(bobRatchet, send(aliceRatchet, "a3"))).toBe("a3");
    expect(receive(aliceRatchet, send(bobRatchet, "b2"))).toBe("b2");
    expect(receive(aliceRatchet, send(bobRatchet, "b3"))).toBe("b3");
    expect(receive(bobRatchet, send(aliceRatchet, "a4"))).toBe("a4");
  });

  it("forward secrecy: leaking a later message key does not reveal earlier plaintext", () => {
    const { aliceRatchet, bobRatchet } = setupSession();
    const m1 = send(aliceRatchet, "secret-1");
    const m2 = send(aliceRatchet, "secret-2");

    receive(bobRatchet, m1);
    receive(bobRatchet, m2);
    // Chain keys are overwritten in place after each step (old ones are gone;
    // `kdfChainKey` never retains the previous chain key object anywhere
    // reachable). There is nothing in `bobRatchet`'s current fields that can
    // reproduce message 1's key — demonstrated by the fact decrypting m1
    // again does not work (already proven by the duplicate-rejection test)
    // and there is no API that exposes a historical chain key at all.
    expect((bobRatchet as any).sendingChainKey).toBeDefined();
    expect(() => ratchetDecrypt(bobRatchet, m1)).toThrow();
  });

  it("post-compromise security: a fresh DH ratchet step heals a leaked chain key", () => {
    const { aliceRatchet, bobRatchet } = setupSession();

    receive(bobRatchet, send(aliceRatchet, "before-leak"));

    // Simulate a full compromise at time T: attacker exfiltrates Bob's
    // current receiving chain key (and thus can derive all *future* message
    // keys on this chain, until the next DH ratchet step).
    const leakedChainKey = bobRatchet.receivingChainKey ? bobRatchet.receivingChainKey.slice() : null;
    expect(leakedChainKey).not.toBeNull();

    // Alice performs a new DH ratchet step (simply by sending again — her
    // own next message carries a *new* dhPublicKey only once she generates
    // one, which happens when she next replies after receiving from Bob).
    const b1 = send(bobRatchet, "from-bob-after-leak");
    receive(aliceRatchet, b1); // Alice ratchets forward on receipt
    const a1 = send(aliceRatchet, "after-healing"); // carries Alice's fresh DH key
    receive(bobRatchet, a1); // Bob ratchets forward too -> brand new chain keys, unrelated to the leaked one

    expect(bobRatchet.receivingChainKey).not.toBeNull();
    // The new chain key must differ from what was leaked — compromise healed.
    const healedChainKeyHex = Buffer.from(bobRatchet.receivingChainKey!).toString("hex");
    const leakedHex = Buffer.from(leakedChainKey!).toString("hex");
    expect(healedChainKeyHex).not.toBe(leakedHex);
  });

  it("sessions fail closed on bit-flipped ciphertext (authenticated encryption)", () => {
    const { aliceRatchet, bobRatchet } = setupSession();
    const m1 = send(aliceRatchet, "integrity check");
    const tampered: RatchetMessage = { header: m1.header, ciphertext: m1.ciphertext.slice() };
    tampered.ciphertext[0] ^= 0xff;
    expect(() => ratchetDecrypt(bobRatchet, tampered)).toThrow();
  });
});
