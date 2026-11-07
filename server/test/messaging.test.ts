import { describe, it, expect } from "vitest";
import request from "supertest";
import { createApp } from "../src/app.js";
import { registerTestUser, authHeader } from "./helpers.js";

const app = createApp();

describe("messages: queue, poll, ack, replay defense-in-depth", () => {
  it("queues a message for an offline recipient and lets them poll + ack it", async () => {
    const alice = await registerTestUser(app, "alice_msg");
    const bob = await registerTestUser(app, "bob_msg");

    const send = await request(app)
      .post("/api/messages")
      .set(authHeader(alice))
      .send({ toDeviceId: bob.deviceId, envelopeType: "ratchet", ciphertext: Buffer.from("opaque-bytes-1").toString("base64") });
    expect(send.status).toBe(201);
    expect(send.body.id).toBeTruthy();

    const poll = await request(app).get("/api/messages").set(authHeader(bob));
    expect(poll.status).toBe(200);
    expect(poll.body.messages).toHaveLength(1);
    expect(poll.body.messages[0].fromAccountId).toBe(alice.accountId);
    expect(Buffer.from(poll.body.messages[0].ciphertext, "base64").toString()).toBe("opaque-bytes-1");

    const ack = await request(app).post("/api/messages/ack").set(authHeader(bob)).send({ messageIds: [poll.body.messages[0].id] });
    expect(ack.status).toBe(200);
    expect(ack.body.deleted).toBe(1);

    const pollAgain = await request(app).get("/api/messages").set(authHeader(bob));
    expect(pollAgain.body.messages).toHaveLength(0);
  });

  it("rejects an exact duplicate ciphertext to the same device (defense in depth)", async () => {
    const alice = await registerTestUser(app, "alice_dup");
    const bob = await registerTestUser(app, "bob_dup");
    const ciphertext = Buffer.from("same-bytes-twice").toString("base64");

    const first = await request(app).post("/api/messages").set(authHeader(alice)).send({ toDeviceId: bob.deviceId, envelopeType: "ratchet", ciphertext });
    expect(first.status).toBe(201);

    const replay = await request(app).post("/api/messages").set(authHeader(alice)).send({ toDeviceId: bob.deviceId, envelopeType: "ratchet", ciphertext });
    expect(replay.status).toBe(202);
    expect(replay.body.duplicate).toBe(true);

    const poll = await request(app).get("/api/messages").set(authHeader(bob));
    expect(poll.body.messages).toHaveLength(1); // only one copy ever reached the queue
  });

  it("omits sender fields when sealedSender is requested", async () => {
    const alice = await registerTestUser(app, "alice_seal");
    const bob = await registerTestUser(app, "bob_seal");

    await request(app)
      .post("/api/messages")
      .set(authHeader(alice))
      .send({ toDeviceId: bob.deviceId, envelopeType: "ratchet", ciphertext: Buffer.from("sealed").toString("base64"), sealedSender: true });

    const poll = await request(app).get("/api/messages").set(authHeader(bob));
    expect(poll.body.messages[0].fromAccountId).toBeNull();
    expect(poll.body.messages[0].fromDeviceId).toBeNull();
  });

  it("rejects sending to an unknown device", async () => {
    const alice = await registerTestUser(app, "alice_unknown");
    const res = await request(app)
      .post("/api/messages")
      .set(authHeader(alice))
      .send({ toDeviceId: "00000000-0000-0000-0000-000000000000", envelopeType: "ratchet", ciphertext: Buffer.from("x").toString("base64") });
    expect(res.status).toBe(404);
  });
});

describe("attachments: encrypted blob upload/download", () => {
  it("round-trips an opaque ciphertext blob", async () => {
    const alice = await registerTestUser(app, "alice_att");
    const ciphertext = Buffer.from("totally-random-looking-ciphertext-bytes");

    const upload = await request(app)
      .post("/api/attachments")
      .set(authHeader(alice))
      .set("content-type", "application/octet-stream")
      .send(ciphertext);
    expect(upload.status).toBe(201);
    expect(upload.body.id).toBeTruthy();

    const download = await request(app).get(`/api/attachments/${upload.body.id}`).set(authHeader(alice));
    expect(download.status).toBe(200);
    expect(Buffer.compare(download.body, ciphertext)).toBe(0);
  });

  it("404s for an unknown attachment id", async () => {
    const alice = await registerTestUser(app, "alice_att2");
    const res = await request(app).get("/api/attachments/00000000-0000-0000-0000-000000000000").set(authHeader(alice));
    expect(res.status).toBe(404);
  });
});

describe("prekeys: fetch consumes one-time prekeys exactly once", () => {
  it("never hands out the same one-time prekey twice", async () => {
    const alice = await registerTestUser(app, "alice_otpk");
    const bob = await registerTestUser(app, "bob_otpk");

    const countBefore = await request(app).get("/api/keys/prekeys/count").set(authHeader(bob));
    expect(countBefore.body.remaining).toBe(10);

    const seen = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const res = await request(app).get(`/api/keys/bundles/${bob.username}`).set(authHeader(alice));
      const otpk = res.body.bundles[0].oneTimePreKeyPublic;
      expect(otpk).toBeTruthy();
      expect(seen.has(otpk)).toBe(false);
      seen.add(otpk);
    }

    const countAfter = await request(app).get("/api/keys/prekeys/count").set(authHeader(bob));
    expect(countAfter.body.remaining).toBe(5);
  });

  it("still returns a bundle (without a one-time prekey) once the pool is exhausted", async () => {
    const alice = await registerTestUser(app, "alice_exhaust");
    const bob = await registerTestUser(app, "bob_exhaust");

    for (let i = 0; i < 10; i++) {
      await request(app).get(`/api/keys/bundles/${bob.username}`).set(authHeader(alice));
    }
    const res = await request(app).get(`/api/keys/bundles/${bob.username}`).set(authHeader(alice));
    expect(res.status).toBe(200);
    expect(res.body.bundles[0].oneTimePreKeyPublic).toBeUndefined();
  });
});
