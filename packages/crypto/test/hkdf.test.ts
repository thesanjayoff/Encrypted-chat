import { describe, it, expect } from "vitest";
import { hkdf, hkdfExtract, hkdfExpand } from "../src/hkdf.js";
import { fromHex, toHex } from "../src/bytes.js";

// Official RFC 5869 test vectors (Appendix A), SHA-256 cases.
describe("HKDF-SHA256 against RFC 5869 official test vectors", () => {
  it("Test Case 1: basic test case with SHA-256", () => {
    const ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = fromHex("000102030405060708090a0b0c");
    const info = fromHex("f0f1f2f3f4f5f6f7f8f9");
    const L = 42;

    const prk = hkdfExtract(salt, ikm);
    expect(toHex(prk)).toBe(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    );

    const okm = hkdfExpand(prk, info, L);
    expect(toHex(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );

    expect(toHex(hkdf(ikm, salt, info, L))).toBe(toHex(okm));
  });

  it("Test Case 2: longer inputs/outputs with SHA-256", () => {
    const ikm = fromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    );
    const salt = fromHex(
      "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    );
    const info = fromHex(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    );
    const L = 82;

    const prk = hkdfExtract(salt, ikm);
    expect(toHex(prk)).toBe(
      "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
    );

    const okm = hkdf(ikm, salt, info, L);
    expect(toHex(okm)).toBe(
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    );
  });

  it("Test Case 3: zero-length salt and info with SHA-256", () => {
    const ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = new Uint8Array(0);
    const info = new Uint8Array(0);
    const L = 42;

    const prk = hkdfExtract(salt, ikm);
    expect(toHex(prk)).toBe(
      "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    );

    const okm = hkdf(ikm, salt, info, L);
    expect(toHex(okm)).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
  });
});
