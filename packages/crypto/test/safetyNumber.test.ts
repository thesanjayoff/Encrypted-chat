import { describe, it, expect } from "vitest";
import { generateIdentityKeyPair } from "../src/keys.js";
import { computeFingerprint, computeSafetyNumber, formatSafetyNumber } from "../src/safetyNumber.js";

describe("Safety numbers", () => {
  it("is deterministic for the same identity", () => {
    const alice = generateIdentityKeyPair();
    const f1 = computeFingerprint({ dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey });
    const f2 = computeFingerprint({ dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey });
    expect(f1).toBe(f2);
    expect(f1).toHaveLength(30);
  });

  it("differs for different identities", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const fa = computeFingerprint({ dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey });
    const fb = computeFingerprint({ dhPublicKey: bob.dh.publicKey, signingPublicKey: bob.signing.publicKey });
    expect(fa).not.toBe(fb);
  });

  it("the combined safety number is order-independent (Alice and Bob compute the same string)", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const aliceId = { dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey };
    const bobId = { dhPublicKey: bob.dh.publicKey, signingPublicKey: bob.signing.publicKey };

    const onAlicesDevice = computeSafetyNumber(aliceId, bobId);
    const onBobsDevice = computeSafetyNumber(bobId, aliceId);

    expect(onAlicesDevice).toBe(onBobsDevice);
    expect(onAlicesDevice).toHaveLength(60);
  });

  it("detects a key change (what the UI warns about)", () => {
    const alice = generateIdentityKeyPair();
    const bob = generateIdentityKeyPair();
    const bobReinstalled = generateIdentityKeyPair(); // Bob reinstalled, or a MITM substituted a key
    const aliceId = { dhPublicKey: alice.dh.publicKey, signingPublicKey: alice.signing.publicKey };
    const bobId = { dhPublicKey: bob.dh.publicKey, signingPublicKey: bob.signing.publicKey };
    const bobReinstalledId = { dhPublicKey: bobReinstalled.dh.publicKey, signingPublicKey: bobReinstalled.signing.publicKey };

    const before = computeSafetyNumber(aliceId, bobId);
    const after = computeSafetyNumber(aliceId, bobReinstalledId);
    expect(before).not.toBe(after);
  });

  it("formats into readable 5-digit blocks", () => {
    const formatted = formatSafetyNumber("1".repeat(60));
    expect(formatted).toBe(Array(12).fill("11111").join(" "));
  });
});
