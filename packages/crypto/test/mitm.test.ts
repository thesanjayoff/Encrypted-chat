import { describe, it, expect } from "vitest";
import { generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, type PreKeyBundle } from "../src/keys.js";
import { x3dhInitiate, x3dhRespond } from "../src/x3dh.js";
import { computeSafetyNumber } from "../src/safetyNumber.js";
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

/**
 * The malicious-server / active-MITM scenario this project's threat model
 * claims to defend against: a server that controls key distribution swaps
 * in an attacker-controlled identity for a victim's, hoping to sit in the
 * middle of the session. X3DH's signature check only proves internal
 * self-consistency of a bundle (the SPK was signed by *whichever* identity
 * key the bundle claims) — a patient attacker who signs their own SPK with
 * their own identity key produces a bundle that is perfectly valid X3DH and
 * will NOT be rejected by x3dhInitiate. That's expected, not a bug: nothing
 * in the key-distribution step alone can authenticate who the other identity
 * key actually belongs to. The second line of defense — out-of-band safety
 * number comparison — is what has to catch this, and this test proves it does.
 */
describe("Active MITM key substitution", () => {
  it("a self-consistent attacker bundle passes X3DH but yields a different safety number than the real contact", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const mallory = generateIdentityKeyPair();

    // Mallory, sitting in for Bob, hands out her OWN identity key with her
    // own (validly self-signed) prekey bundle — the server/network attacker
    // scenario, not a forged signature.
    const malloryAsBob = generateSignedPreKey(mallory.signing.privateKey, 1);
    const [malloryOtpk] = generateOneTimePreKeys(1, 1);
    const substitutedBundle = bundleFor(mallory, malloryAsBob, malloryOtpk);

    // Alice has no way to know this bundle isn't really Bob's — X3DH succeeds.
    const aliceResult = x3dhInitiate(alice, substitutedBundle);
    const malloryResult = x3dhRespond(mallory, malloryAsBob, malloryOtpk, alice.dh.publicKey, aliceResult.ephemeralKeyPair.publicKey);
    expect(toHex(aliceResult.sharedSecret)).toBe(toHex(malloryResult.sharedSecret));
    // The session is live and working — between Alice and Mallory, not Bob.

    // What the UI actually shows Alice is a safety number computed from the
    // identity key she received, labeled as Bob's.
    const safetyNumberAliceSees = computeSafetyNumber(
      { dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey },
      { dhPublicKey: mallory.dh.publicKey, signingPublicKey: mallory.signing.publicKey },
    );

    // What the real Bob would read aloud (or show as a QR code) out-of-band,
    // computed from his own actual identity key.
    const safetyNumberBobWouldShow = computeSafetyNumber(
      { dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey },
      { dhPublicKey: bob.dh.publicKey, signingPublicKey: bob.signing.publicKey },
    );

    // The mismatch is exactly the signal the app's "safety number" / contact
    // verification UI relies on to catch this attack.
    expect(safetyNumberAliceSees).not.toBe(safetyNumberBobWouldShow);
  });

  it("control: no substitution means Alice's and Bob's safety numbers do match", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const bobSpk = generateSignedPreKey(bob.signing.privateKey, 1);
    const [bobOtpk] = generateOneTimePreKeys(1, 1);
    const realBundle = bundleFor(bob, bobSpk, bobOtpk);

    const aliceResult = x3dhInitiate(alice, realBundle);
    const bobResult = x3dhRespond(bob, bobSpk, bobOtpk, alice.dh.publicKey, aliceResult.ephemeralKeyPair.publicKey);
    expect(toHex(aliceResult.sharedSecret)).toBe(toHex(bobResult.sharedSecret));

    const onAlicesDevice = computeSafetyNumber(
      { dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey },
      { dhPublicKey: bob.dh.publicKey, signingPublicKey: bob.signing.publicKey },
    );
    const onBobsDevice = computeSafetyNumber(
      { dhPublicKey: bob.dh.publicKey, signingPublicKey: bob.signing.publicKey },
      { dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey },
    );
    expect(onAlicesDevice).toBe(onBobsDevice);
  });
});
