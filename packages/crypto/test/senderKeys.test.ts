import { describe, it, expect } from "vitest";
import {
  createSenderKeyState,
  receiveSenderKeyDistribution,
  senderKeyEncrypt,
  senderKeyDecrypt,
} from "../src/senderKeys.js";
import { utf8, fromUtf8 } from "../src/bytes.js";

describe("Sender Keys (group messaging)", () => {
  it("one sender, multiple recipients, round trip", () => {
    const { state: senderState, distribution } = createSenderKeyState();
    const bobCopy = receiveSenderKeyDistribution(distribution);
    const carolCopy = receiveSenderKeyDistribution(distribution);

    const msg = senderKeyEncrypt(senderState, utf8("hello group"));

    expect(fromUtf8(senderKeyDecrypt(bobCopy, msg))).toBe("hello group");
    expect(fromUtf8(senderKeyDecrypt(carolCopy, msg))).toBe("hello group");
  });

  it("handles out-of-order group message delivery", () => {
    const { state: senderState, distribution } = createSenderKeyState();
    const bobCopy = receiveSenderKeyDistribution(distribution);

    const m1 = senderKeyEncrypt(senderState, utf8("1"));
    const m2 = senderKeyEncrypt(senderState, utf8("2"));
    const m3 = senderKeyEncrypt(senderState, utf8("3"));

    expect(fromUtf8(senderKeyDecrypt(bobCopy, m3))).toBe("3");
    expect(fromUtf8(senderKeyDecrypt(bobCopy, m1))).toBe("1");
    expect(fromUtf8(senderKeyDecrypt(bobCopy, m2))).toBe("2");
  });

  it("rejects a message signed with a different sender's key (impersonation attempt)", () => {
    const { state: aliceState, distribution: aliceDist } = createSenderKeyState();
    const { state: mallorySenderState } = createSenderKeyState(); // Mallory also has *a* chain key for the group

    const bobCopyOfAlice = receiveSenderKeyDistribution(aliceDist);

    // Mallory crafts a message and tries to pass it off, but she signs with
    // her own key while claiming to be a message from Alice's chain — the
    // signature is checked against Alice's distributed signingPublicKey, so
    // this must fail even though Mallory is a legitimate group member with
    // her own valid Sender Key.
    const forged = senderKeyEncrypt(mallorySenderState, utf8("forged"));
    expect(() => senderKeyDecrypt(bobCopyOfAlice, forged)).toThrow();
  });

  it("a removed member cannot decrypt messages sent after Sender Key rotation", () => {
    const { state: aliceStateEpoch1, distribution: dist1 } = createSenderKeyState();
    const bobCopyEpoch1 = receiveSenderKeyDistribution(dist1);
    const carolCopyEpoch1 = receiveSenderKeyDistribution(dist1); // Carol is about to be removed

    const before = senderKeyEncrypt(aliceStateEpoch1, utf8("before removal"));
    expect(fromUtf8(senderKeyDecrypt(carolCopyEpoch1, before))).toBe("before removal");

    // Carol is removed -> Alice rotates her Sender Key and redistributes
    // ONLY to Bob (the remaining member). Carol never receives dist2.
    const { state: aliceStateEpoch2, distribution: dist2 } = createSenderKeyState();
    const bobCopyEpoch2 = receiveSenderKeyDistribution(dist2);

    const after = senderKeyEncrypt(aliceStateEpoch2, utf8("after removal"));
    expect(fromUtf8(senderKeyDecrypt(bobCopyEpoch2, after))).toBe("after removal");

    // Carol only has the epoch-1 state; it cannot decrypt an epoch-2 message
    // (different chain key entirely, not just a few steps ahead).
    expect(() => senderKeyDecrypt(carolCopyEpoch1, after)).toThrow();
    void bobCopyEpoch1;
  });
});
