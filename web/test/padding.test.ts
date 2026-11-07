import { describe, it, expect } from "vitest";
import { utf8, fromUtf8, randomBytes } from "@e2e-chat/crypto";
import { padMessage, unpadMessage } from "../src/lib/padding.js";

describe("padMessage / unpadMessage round trip", () => {
  it("recovers the exact original plaintext for a range of sizes", () => {
    for (const len of [0, 1, 4, 255, 256, 257, 1023, 1024, 16383, 16384, 16385, 40000]) {
      const plaintext = randomBytes(len);
      const padded = padMessage(plaintext);
      expect(padded.length % 256 === 0 || padded.length >= 16384).toBe(true);
      const recovered = unpadMessage(padded);
      expect(recovered).toEqual(plaintext);
    }
  });

  it("recovers readable text through the full pipeline", () => {
    const text = "hello from alice";
    const recovered = fromUtf8(unpadMessage(padMessage(utf8(text))));
    expect(recovered).toBe(text);
  });
});

/**
 * unpadMessage reads an attacker/server-controlled 4-byte length prefix and
 * slices the buffer accordingly — exactly the kind of parsing step that
 * must never read out of bounds or crash on a malicious or corrupted
 * message, only ever return the right bytes or throw a clean Error.
 */
describe("Fuzz: unpadMessage against adversarial input", () => {
  it("never crashes on fully random byte buffers — only decodes or throws", () => {
    for (let i = 0; i < 300; i++) {
      const len = Math.floor(Math.random() * 20);
      const garbage = randomBytes(len);
      try {
        const result = unpadMessage(garbage);
        expect(result).toBeInstanceOf(Uint8Array);
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
      }
    }
  });

  it("rejects a length prefix larger than the buffer instead of over-reading", () => {
    const buf = new Uint8Array(8);
    buf[0] = 0xff;
    buf[1] = 0xff;
    buf[2] = 0xff;
    buf[3] = 0xff; // length = 0xffffffff, buffer is only 8 bytes
    expect(() => unpadMessage(buf)).toThrow(/corrupt padding length/);
  });

  it("rejects anything shorter than the 4-byte length prefix", () => {
    for (const len of [0, 1, 2, 3]) {
      expect(() => unpadMessage(randomBytes(len))).toThrow(/too short/);
    }
  });
});
