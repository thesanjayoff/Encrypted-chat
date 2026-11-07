import { describe, it, expect } from "vitest";
import request from "supertest";
import { generateSignedPreKey, generateOneTimePreKeys, toBase64 } from "@e2e-chat/crypto";
import { createApp } from "../src/app.js";
import { registerTestUser, authHeader } from "./helpers.js";

const app = createApp();

describe("device linking", () => {
  it("registers a second device under the same account via a one-time link token", async () => {
    const primary = await registerTestUser(app, "alice_dev");

    const linkStart = await request(app).post("/api/devices/link/start").set(authHeader(primary));
    expect(linkStart.status).toBe(201);
    const { linkToken } = linkStart.body;
    expect(linkToken).toBeTruthy();

    // The new device would normally receive the account's real identity key
    // pair over the end-to-end relay channel (ws/linkRelay.ts) keyed by this
    // same token. Here we reuse `primary.identity` directly to stand in for
    // "the identity key material this device received over that channel."
    const newDeviceSpk = generateSignedPreKey(primary.identity.signing.privateKey, 2);
    const newDeviceOtpks = generateOneTimePreKeys(1, 5);

    const register = await request(app)
      .post("/api/devices/link/register")
      .send({
        linkToken,
        identitySigningPublicKey: toBase64(primary.identity.signing.publicKey),
        identityDhKey: toBase64(primary.identity.dh.publicKey),
        device: {
          label: "laptop",
          signedPreKeyId: newDeviceSpk.keyId,
          signedPreKeyPublic: toBase64(newDeviceSpk.keyPair.publicKey),
          signedPreKeySignature: toBase64(newDeviceSpk.signature),
          oneTimePreKeys: newDeviceOtpks.map((o) => ({ keyId: o.keyId, publicKey: toBase64(o.keyPair.publicKey) })),
        },
      });
    expect(register.status).toBe(201);
    expect(register.body.accountId).toBe(primary.accountId);
    expect(register.body.deviceId).not.toBe(primary.deviceId);
    expect(register.body.sessionToken).toBeTruthy();

    const devices = await request(app).get("/api/devices").set(authHeader(primary));
    expect(devices.body.devices).toHaveLength(2);
  });

  it("rejects a link token that was already used", async () => {
    const primary = await registerTestUser(app, "bob_dev");
    const linkStart = await request(app).post("/api/devices/link/start").set(authHeader(primary));
    const { linkToken } = linkStart.body;

    const spk = generateSignedPreKey(primary.identity.signing.privateKey, 2);
    const otpks = generateOneTimePreKeys(1, 1);
    const payload = {
      linkToken,
      identitySigningPublicKey: toBase64(primary.identity.signing.publicKey),
      identityDhKey: toBase64(primary.identity.dh.publicKey),
      device: {
        signedPreKeyId: spk.keyId,
        signedPreKeyPublic: toBase64(spk.keyPair.publicKey),
        signedPreKeySignature: toBase64(spk.signature),
        oneTimePreKeys: otpks.map((o) => ({ keyId: o.keyId, publicKey: toBase64(o.keyPair.publicKey) })),
      },
    };

    const first = await request(app).post("/api/devices/link/register").send(payload);
    expect(first.status).toBe(201);

    const second = await request(app).post("/api/devices/link/register").send(payload);
    expect(second.status).toBe(401);
  });

  it("rejects identity key material that doesn't match the linking account", async () => {
    const primary = await registerTestUser(app, "carol_dev");
    const other = await registerTestUser(app, "dave_dev");
    const linkStart = await request(app).post("/api/devices/link/start").set(authHeader(primary));

    const spk = generateSignedPreKey(other.identity.signing.privateKey, 2);
    const otpks = generateOneTimePreKeys(1, 1);

    const res = await request(app)
      .post("/api/devices/link/register")
      .send({
        linkToken: linkStart.body.linkToken,
        identitySigningPublicKey: toBase64(other.identity.signing.publicKey), // wrong identity
        identityDhKey: toBase64(other.identity.dh.publicKey),
        device: {
          signedPreKeyId: spk.keyId,
          signedPreKeyPublic: toBase64(spk.keyPair.publicKey),
          signedPreKeySignature: toBase64(spk.signature),
          oneTimePreKeys: otpks.map((o) => ({ keyId: o.keyId, publicKey: toBase64(o.keyPair.publicKey) })),
        },
      });
    expect(res.status).toBe(403);
  });
});
