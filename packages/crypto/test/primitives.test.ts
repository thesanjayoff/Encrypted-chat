import { describe, it, expect } from "vitest";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { fromHex, toHex } from "../src/bytes.js";

// Every primitive the protocol layer is built on is checked here against an
// official spec test vector before it is trusted anywhere else in this repo.

describe("HMAC-SHA256 against RFC 4231 Test Case 2", () => {
  it("matches the known-answer digest", () => {
    const key = fromHex("4a656665"); // "Jefe"
    const data = fromHex("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
    const digest = hmac(sha256, key, data);
    expect(toHex(digest)).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
  });
});

describe("Ed25519 against RFC 8032 section 7.1 TEST 1", () => {
  it("derives the published public key from the seed", () => {
    const seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".slice(0, 64));
    const pub = ed25519.getPublicKey(seed);
    expect(toHex(pub)).toBe(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".slice(0, 64),
    );
  });

  it("produces the published signature over an empty message", () => {
    const seed = fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".slice(0, 64));
    const message = new Uint8Array(0);
    const sig = ed25519.sign(message, seed);
    expect(toHex(sig)).toBe(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
  });

  it("verifies the published signature", () => {
    const pub = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".slice(0, 64));
    const sig = fromHex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    expect(ed25519.verify(sig, new Uint8Array(0), pub)).toBe(true);
  });
});

describe("X25519 against RFC 7748 section 5.2 first test vector", () => {
  it("matches the published output u-coordinate", () => {
    const scalar = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4".slice(0, 64));
    const u = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c".slice(0, 64));
    const out = x25519.getSharedSecret(scalar, u);
    expect(toHex(out)).toBe(
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552".slice(0, 64),
    );
  });
});

describe("ChaCha20-Poly1305 against RFC 8439 section 2.8.2", () => {
  it("matches the published ciphertext and tag", () => {
    const plaintext = fromHex(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    );
    const aad = fromHex("50515253c0c1c2c3c4c5c6c7");
    const key = fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const nonce = fromHex("070000004041424344454647");

    const cipher = chacha20poly1305(key, nonce, aad);
    const sealed = cipher.encrypt(plaintext);

    const expectedCiphertext =
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    const expectedTag = "1ae10b594f09e26a7e902ecbd0600691".slice(0, 32);

    expect(toHex(sealed)).toBe(expectedCiphertext + expectedTag);

    const decipher = chacha20poly1305(key, nonce, aad);
    expect(toHex(decipher.decrypt(sealed))).toBe(toHex(plaintext));
  });
});
