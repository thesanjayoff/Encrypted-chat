import { describe, it, expect } from "vitest";
import request from "supertest";
import { createApp } from "../src/app.js";
import { registerTestUser, authHeader } from "./helpers.js";

const app = createApp();

describe("groups: membership and fan-out", () => {
  it("creates a group and fans a message out to every other member's device", async () => {
    const alice = await registerTestUser(app, "alice_grp");
    const bob = await registerTestUser(app, "bob_grp");
    const carol = await registerTestUser(app, "carol_grp");

    const create = await request(app).post("/api/groups").set(authHeader(alice)).send({ memberUsernames: [bob.username, carol.username] });
    expect(create.status).toBe(201);
    const groupId = create.body.groupId;
    expect(create.body.members).toHaveLength(3);

    // Membership-changed control notices should already be queued for Bob and Carol.
    const bobQueueAfterCreate = await request(app).get("/api/messages").set(authHeader(bob));
    expect(bobQueueAfterCreate.body.messages.some((m: any) => m.envelopeType === "control")).toBe(true);
    await request(app).post("/api/messages/ack").set(authHeader(bob)).send({ messageIds: bobQueueAfterCreate.body.messages.map((m: any) => m.id) });

    const ciphertext = Buffer.from("sender-key-encrypted-group-message").toString("base64");
    const send = await request(app).post(`/api/groups/${groupId}/messages`).set(authHeader(alice)).send({ ciphertext });
    expect(send.status).toBe(201);
    expect(send.body.fannedOutTo).toBe(2); // bob + carol, not alice's own device

    const bobQueue = await request(app).get("/api/messages").set(authHeader(bob));
    const carolQueue = await request(app).get("/api/messages").set(authHeader(carol));
    expect(bobQueue.body.messages.some((m: any) => m.envelopeType === "senderkey")).toBe(true);
    expect(carolQueue.body.messages.some((m: any) => m.envelopeType === "senderkey")).toBe(true);
  });

  it("notifies remaining members on removal (so they rotate Sender Keys) and stops fanning out to the removed member", async () => {
    const alice = await registerTestUser(app, "alice_grp2");
    const bob = await registerTestUser(app, "bob_grp2");
    const carol = await registerTestUser(app, "carol_grp2");

    const create = await request(app).post("/api/groups").set(authHeader(alice)).send({ memberUsernames: [bob.username, carol.username] });
    const groupId = create.body.groupId;

    // Drain initial control-notice queues.
    for (const u of [bob, carol]) {
      const q = await request(app).get("/api/messages").set(authHeader(u));
      await request(app).post("/api/messages/ack").set(authHeader(u)).send({ messageIds: q.body.messages.map((m: any) => m.id) });
    }

    const remove = await request(app).post(`/api/groups/${groupId}/members`).set(authHeader(alice)).send({ removeAccountIds: [carol.accountId] });
    expect(remove.status).toBe(200);
    expect(remove.body.members).toHaveLength(2);
    expect(remove.body.members).not.toContain(carol.accountId);

    // Bob (remaining) gets a membership-changed notice so his client rotates+redistributes the Sender Key.
    const bobQueue = await request(app).get("/api/messages").set(authHeader(bob));
    expect(bobQueue.body.messages.some((m: any) => m.envelopeType === "control")).toBe(true);

    const sendAfter = await request(app)
      .post(`/api/groups/${groupId}/messages`)
      .set(authHeader(alice))
      .send({ ciphertext: Buffer.from("after-removal").toString("base64") });
    expect(sendAfter.body.fannedOutTo).toBe(1); // only Bob now

    const carolQueueAfter = await request(app).get("/api/messages").set(authHeader(carol));
    // Carol may still have the earlier membership-changed notice queued from
    // before her removal, but she must receive nothing from the post-removal send.
    expect(carolQueueAfter.body.messages.some((m: any) => m.ciphertext === Buffer.from("after-removal").toString("base64"))).toBe(false);
  });

  it("rejects a message send from a non-member", async () => {
    const alice = await registerTestUser(app, "alice_grp3");
    const bob = await registerTestUser(app, "bob_grp3");
    const outsider = await registerTestUser(app, "outsider_grp3");

    const create = await request(app).post("/api/groups").set(authHeader(alice)).send({ memberUsernames: [bob.username] });
    const res = await request(app)
      .post(`/api/groups/${create.body.groupId}/messages`)
      .set(authHeader(outsider))
      .send({ ciphertext: Buffer.from("x").toString("base64") });
    expect(res.status).toBe(403);
  });
});
