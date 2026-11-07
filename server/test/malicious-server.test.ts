import { describe, it, expect } from "vitest";
import request from "supertest";
import {
  x3dhInitiate,
  ratchetInitAlice,
  ratchetEncrypt,
  toBase64,
  utf8,
} from "@e2e-chat/crypto";
import { createApp } from "../src/app.js";
import { db } from "../src/db.js";
import { registerTestUser, authHeader } from "./helpers.js";

const app = createApp();

/**
 * This is the test the project brief explicitly asks for: simulate a full
 * conversation through the real HTTP API, then act as a fully malicious
 * server operator — dump *everything* in the database — and assert that no
 * plaintext, no private key, and no password ever ends up somewhere a
 * server operator could read it.
 */
describe("malicious server: full database dump after a real conversation", () => {
  it("contains no plaintext, no private key material, and no password anywhere", async () => {
    const SECRET_PLAINTEXT = "the launch codes are 00000-ZEBRA-whiskey";

    const alice = await registerTestUser(app, "alice_mal");
    const bob = await registerTestUser(app, "bob_mal");

    // Fetch Bob's bundle exactly as a real client would, run real X3DH +
    // Double Ratchet, and send a real encrypted first message.
    const bundlesRes = await request(app).get(`/api/keys/bundles/${bob.username}`).set(authHeader(alice));
    expect(bundlesRes.status).toBe(200);
    const bobBundle = bundlesRes.body.bundles[0];

    const x3dh = x3dhInitiate(alice.identity, {
      identitySigningKey: Buffer.from(bobBundle.identitySigningKey, "base64"),
      identityDhKey: Buffer.from(bobBundle.identityDhKey, "base64"),
      signedPreKeyId: bobBundle.signedPreKeyId,
      signedPreKeyPublic: Buffer.from(bobBundle.signedPreKeyPublic, "base64"),
      signedPreKeySignature: Buffer.from(bobBundle.signedPreKeySignature, "base64"),
      oneTimePreKeyId: bobBundle.oneTimePreKeyId,
      oneTimePreKeyPublic: bobBundle.oneTimePreKeyPublic ? Buffer.from(bobBundle.oneTimePreKeyPublic, "base64") : undefined,
    });

    const ratchet = ratchetInitAlice(x3dh.sharedSecret, x3dh.associatedData, Buffer.from(bobBundle.signedPreKeyPublic, "base64"));
    const { header, ciphertext } = ratchetEncrypt(ratchet, utf8(SECRET_PLAINTEXT));

    const envelope = {
      header: { dhPublicKey: toBase64(header.dhPublicKey), previousChainLength: header.previousChainLength, messageNumber: header.messageNumber },
      ephemeralPublicKey: toBase64(x3dh.ephemeralKeyPair.publicKey),
      oneTimePreKeyId: bobBundle.oneTimePreKeyId,
      ciphertext: toBase64(ciphertext),
    };

    const sendRes = await request(app)
      .post("/api/messages")
      .set(authHeader(alice))
      .send({
        toDeviceId: bobBundle.deviceId,
        envelopeType: "prekey",
        ciphertext: toBase64(utf8(JSON.stringify(envelope))),
      });
    expect(sendRes.status).toBe(201);

    // Also exercise contacts, groups, and attachments so the dump covers
    // every table a "store and forward ciphertext only" server should have.
    await request(app).post("/api/contacts").set(authHeader(alice)).send({ username: bob.username });
    await request(app).post("/api/groups").set(authHeader(alice)).send({ memberUsernames: [bob.username] });
    await request(app)
      .post("/api/attachments")
      .set(authHeader(alice))
      .set("content-type", "application/octet-stream")
      .send(Buffer.from("not-really-a-photo-but-pretend-this-is-ciphertext"));

    // --- Now: act as a fully malicious server operator with raw DB access ---
    const tableNames = (db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`).all() as { name: string }[]).map((r) => r.name);
    expect(tableNames.length).toBeGreaterThan(0);

    const forbiddenStrings = [
      SECRET_PLAINTEXT,
      alice.password,
      bob.password,
      Buffer.from(alice.identity.signing.privateKey).toString("base64"),
      Buffer.from(alice.identity.dh.privateKey).toString("base64"),
      Buffer.from(alice.signedPreKey.keyPair.privateKey).toString("base64"),
      Buffer.from(ratchet.dhSelf.privateKey).toString("base64"),
      Buffer.from(bob.identity.signing.privateKey).toString("base64"),
      Buffer.from(bob.identity.dh.privateKey).toString("base64"),
      Buffer.from(bob.signedPreKey.keyPair.privateKey).toString("base64"),
    ];

    function allValuesAsStrings(row: Record<string, unknown>): string[] {
      return Object.values(row).map((v) => {
        if (v == null) return "";
        if (Buffer.isBuffer(v)) return v.toString("base64") + "\n" + v.toString("utf8") + "\n" + v.toString("hex");
        return String(v);
      });
    }

    let inspectedRows = 0;
    for (const table of tableNames) {
      const rows = db.prepare(`SELECT * FROM ${table}`).all() as Record<string, unknown>[];
      for (const row of rows) {
        inspectedRows++;
        const haystacks = allValuesAsStrings(row);
        for (const forbidden of forbiddenStrings) {
          for (const haystack of haystacks) {
            expect(haystack.includes(forbidden)).toBe(false);
          }
        }
      }
    }
    expect(inspectedRows).toBeGreaterThan(0);

    // Sanity: the message row DOES exist and DOES contain our ciphertext
    // blob (proving we actually inspected real stored data, not an empty DB).
    const messageRows = db.prepare(`SELECT * FROM messages`).all() as { ciphertext: Buffer }[];
    expect(messageRows.length).toBeGreaterThan(0);
    const anyCiphertextContainsPlaintext = messageRows.some((r) => r.ciphertext.toString("utf8").includes(SECRET_PLAINTEXT));
    expect(anyCiphertextContainsPlaintext).toBe(false);
  });
});
