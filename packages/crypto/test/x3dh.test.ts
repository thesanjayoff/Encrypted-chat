import { describe, it, expect } from "vitest";
import { generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, type PreKeyBundle } from "../src/keys.js";
import { x3dhInitiate, x3dhRespond, X3DHVerificationError } from "../src/x3dh.js";
import { toHex } from "../src/bytes.js";

function bundleFor(identity: ReturnType<typeof generateIdentityKeyPair>, spk: ReturnType<typeof generateSignedPreKey>, otpk?: ReturnType<typeof generateOneTimePreKeys>[number]): PreKeyBundle {
  return {
    identitySigningKey: identity.signing.publicKey,
    identityDhKey: identity.dh.publicKey,
    signedPreKeyId: spk.keyId,
    signedPreKeyPublic: spk.keyPair.publicKey,
    signedPreKeySignature: spk.signature,
    oneTimePreKeyId: otpk?.keyId,
    oneTimePreKeyPublic: otpk?.keyPair.publicKey,
  };
}

describe("X3DH", () => {
  it("Alice and Bob derive the identical shared secret and associated data (with a one-time prekey)", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const bobSpk = generateSignedPreKey(bob.signing.privateKey, 1);
    const bobOtpks = generateOneTimePreKeys(1, 5);
    const bobOtpk = bobOtpks[0];

    const bundle = bundleFor(bob, bobSpk, bobOtpk);

    const aliceResult = x3dhInitiate(alice, bundle);

    const bobResult = x3dhRespond(
      bob,
      bobSpk,
      bobOtpk,
      alice.dh.publicKey,
      aliceResult.ephemeralKeyPair.publicKey,
    );

    expect(toHex(aliceResult.sharedSecret)).toBe(toHex(bobResult.sharedSecret));
    expect(toHex(aliceResult.associatedData)).toBe(toHex(bobResult.associatedData));
  });

  it("works without a one-time prekey (pool exhausted)", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const bobSpk = generateSignedPreKey(bob.signing.privateKey, 1);
    const bundle = bundleFor(bob, bobSpk);

    const aliceResult = x3dhInitiate(alice, bundle);
    const bobResult = x3dhRespond(bob, bobSpk, undefined, alice.dh.publicKey, aliceResult.ephemeralKeyPair.publicKey);

    expect(toHex(aliceResult.sharedSecret)).toBe(toHex(bobResult.sharedSecret));
  });

  it("rejects a bundle whose Signed PreKey signature does not verify", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const mallory = generateIdentityKeyPair();
    const bobSpk = generateSignedPreKey(bob.signing.privateKey, 1);
    // Server (or MITM) swapped in a different identity signing key than the one that actually signed the SPK.
    const tamperedBundle = bundleFor(bob, bobSpk);
    tamperedBundle.identitySigningKey = mallory.signing.publicKey;

    expect(() => x3dhInitiate(alice, tamperedBundle)).toThrow(X3DHVerificationError);
  });

  it("produces a different shared secret for a different one-time prekey (unknown-key-share resistance sanity check)", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const bobSpk = generateSignedPreKey(bob.signing.privateKey, 1);
    const [otpk1, otpk2] = generateOneTimePreKeys(1, 2);

    const r1 = x3dhInitiate(alice, bundleFor(bob, bobSpk, otpk1));
    const r2 = x3dhInitiate(alice, bundleFor(bob, bobSpk, otpk2));

    expect(toHex(r1.sharedSecret)).not.toBe(toHex(r2.sharedSecret));
  });
});
