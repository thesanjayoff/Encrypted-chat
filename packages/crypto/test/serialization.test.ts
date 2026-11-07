import { describe, it, expect } from "vitest";
import { generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, type PreKeyBundle } from "../src/keys.js";
import { x3dhInitiate, x3dhRespond } from "../src/x3dh.js";
import { ratchetInitAlice, ratchetInitBob, ratchetEncrypt, ratchetDecrypt, DoubleRatchetState } from "../src/doubleRatchet.js";
import { createSenderKeyState, receiveSenderKeyDistribution, senderKeyEncrypt, senderKeyDecrypt, SenderKeyState } from "../src/senderKeys.js";
import { utf8, fromUtf8 } from "../src/bytes.js";

describe("Double Ratchet state round-trips through JSON (local storage persistence)", () => {
  it("a reloaded state can still send and receive correctly", () => {
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

    let aliceRatchet = ratchetInitAlice(aliceX3dh.sharedSecret, aliceX3dh.associatedData, bobSpk.keyPair.publicKey);
    const bobRatchet = ratchetInitBob(bobX3dh.sharedSecret, bobX3dh.associatedData, bobSpk.keyPair);

    const m1 = ratchetEncrypt(aliceRatchet, utf8("before reload"));

    // Simulate closing and reopening the app: serialize, reconstruct.
    const reloaded = DoubleRatchetState.fromJSON(JSON.parse(JSON.stringify(aliceRatchet.toJSON())));
    aliceRatchet = reloaded;

    expect(fromUtf8(ratchetDecrypt(bobRatchet, m1))).toBe("before reload");

    const m2 = ratchetEncrypt(aliceRatchet, utf8("after reload"));
    expect(fromUtf8(ratchetDecrypt(bobRatchet, m2))).toBe("after reload");
  });
});

describe("Sender Key state round-trips through JSON", () => {
  it("a reloaded recipient state can still decrypt subsequent messages", () => {
    const { state: senderState, distribution } = createSenderKeyState();
    let bobCopy = receiveSenderKeyDistribution(distribution);

    const m1 = senderKeyEncrypt(senderState, utf8("one"));
    expect(fromUtf8(senderKeyDecrypt(bobCopy, m1))).toBe("one");

    bobCopy = SenderKeyState.fromJSON(JSON.parse(JSON.stringify(bobCopy.toJSON())));

    const m2 = senderKeyEncrypt(senderState, utf8("two"));
    expect(fromUtf8(senderKeyDecrypt(bobCopy, m2))).toBe("two");
  });

  it("a reloaded sender state (with private key) can still encrypt", () => {
    const { state: senderState, distribution } = createSenderKeyState();
    const bobCopy = receiveSenderKeyDistribution(distribution);

    const reloadedSender = SenderKeyState.fromJSON(JSON.parse(JSON.stringify(senderState.toJSON())));
    const m1 = senderKeyEncrypt(reloadedSender, utf8("from reloaded sender"));
    expect(fromUtf8(senderKeyDecrypt(bobCopy, m1))).toBe("from reloaded sender");
  });
});
