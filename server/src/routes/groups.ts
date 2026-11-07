import { Router } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { db } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { apiLimiter } from "../middleware/rateLimit.js";
import { enqueueMessage, DEFAULT_RETENTION_MS } from "../deliver.js";

export const groupsRouter = Router();

// The server stores group membership only to know who to fan a ciphertext
// out to. It never sees a group name, avatar, or member nickname — those
// are exchanged end-to-end between members (e.g. as the very first message
// in the group's own Sender Key stream) and rendered client-side only.

interface DeviceRow {
  id: string;
  account_id: string;
}

function allDevicesOf(accountIds: string[]): DeviceRow[] {
  if (accountIds.length === 0) return [];
  const placeholders = accountIds.map(() => "?").join(",");
  return db.prepare(`SELECT id, account_id FROM devices WHERE account_id IN (${placeholders})`).all(...accountIds) as DeviceRow[];
}

function memberIds(groupId: string): string[] {
  return (db.prepare(`SELECT account_id FROM group_members WHERE group_id = ?`).all(groupId) as { account_id: string }[]).map((r) => r.account_id);
}

function notifyMembershipChanged(groupId: string, excludeDeviceId?: string) {
  const members = memberIds(groupId);
  const devices = allDevicesOf(members);
  const payload = Buffer.from(JSON.stringify({ kind: "group-membership-changed", groupId, members }));
  for (const d of devices) {
    if (d.id === excludeDeviceId) continue;
    enqueueMessage({
      toAccountId: d.account_id,
      toDeviceId: d.id,
      fromAccountId: null,
      fromDeviceId: null,
      envelopeType: "control",
      ciphertext: payload,
      ttlMs: 10 * 60 * 1000,
    });
  }
}

const createSchema = z.object({ memberUsernames: z.array(z.string()).min(1).max(256) });

groupsRouter.post("/", requireAuth, apiLimiter, (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const memberAccounts = db
    .prepare(`SELECT id, username FROM accounts WHERE username IN (${parsed.data.memberUsernames.map(() => "?").join(",")})`)
    .all(...parsed.data.memberUsernames) as { id: string; username: string }[];

  const groupId = randomUUID();
  const now = Date.now();
  const allMemberIds = new Set([req.session!.accountId, ...memberAccounts.map((m) => m.id)]);

  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO groups (id, created_by_account_id, created_at) VALUES (?, ?, ?)`).run(groupId, req.session!.accountId, now);
    const insertMember = db.prepare(`INSERT INTO group_members (group_id, account_id, added_at) VALUES (?, ?, ?)`);
    for (const id of allMemberIds) insertMember.run(groupId, id, now);
  });
  tx();

  notifyMembershipChanged(groupId);
  res.status(201).json({ groupId, members: [...allMemberIds] });
});

groupsRouter.get("/", requireAuth, apiLimiter, (req, res) => {
  const rows = db
    .prepare(`SELECT group_id FROM group_members WHERE account_id = ?`)
    .all(req.session!.accountId) as { group_id: string }[];
  const groups = rows.map((r) => ({ groupId: r.group_id, members: memberIds(r.group_id) }));
  res.json({ groups });
});

const updateMembersSchema = z.object({
  addUsernames: z.array(z.string()).max(256).optional(),
  removeAccountIds: z.array(z.string().uuid()).max(256).optional(),
});

groupsRouter.post("/:id/members", requireAuth, apiLimiter, (req, res) => {
  const groupId = req.params.id;
  const isMember = db.prepare(`SELECT 1 FROM group_members WHERE group_id = ? AND account_id = ?`).get(groupId, req.session!.accountId);
  if (!isMember) {
    res.status(403).json({ error: "not a member of this group" });
    return;
  }
  const parsed = updateMembersSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }

  const tx = db.transaction(() => {
    const now = Date.now();
    if (parsed.data.addUsernames?.length) {
      const accounts = db
        .prepare(`SELECT id FROM accounts WHERE username IN (${parsed.data.addUsernames.map(() => "?").join(",")})`)
        .all(...parsed.data.addUsernames) as { id: string }[];
      const insert = db.prepare(`INSERT OR IGNORE INTO group_members (group_id, account_id, added_at) VALUES (?, ?, ?)`);
      for (const a of accounts) insert.run(groupId, a.id, now);
    }
    if (parsed.data.removeAccountIds?.length) {
      const del = db.prepare(`DELETE FROM group_members WHERE group_id = ? AND account_id = ?`);
      for (const id of parsed.data.removeAccountIds) del.run(groupId, id);
    }
  });
  tx();

  // Every remaining member must now rotate+redistribute their Sender Key —
  // this is precisely what keeps a removed member from reading new messages.
  notifyMembershipChanged(groupId);
  res.json({ members: memberIds(groupId) });
});

const sendSchema = z.object({
  ciphertext: z.string().min(1),
  ttlSeconds: z.number().int().positive().max(DEFAULT_RETENTION_MS / 1000).optional(),
});

groupsRouter.post("/:id/messages", requireAuth, apiLimiter, (req, res) => {
  const groupId = req.params.id;
  const isMember = db.prepare(`SELECT 1 FROM group_members WHERE group_id = ? AND account_id = ?`).get(groupId, req.session!.accountId);
  if (!isMember) {
    res.status(403).json({ error: "not a member of this group" });
    return;
  }
  const parsed = sendSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }

  const members = memberIds(groupId);
  const devices = allDevicesOf(members);
  const ciphertext = Buffer.from(parsed.data.ciphertext, "base64");

  let delivered = 0;
  for (const d of devices) {
    if (d.id === req.session!.deviceId) continue; // sender's own device doesn't need an echo
    enqueueMessage({
      toAccountId: d.account_id,
      toDeviceId: d.id,
      fromAccountId: req.session!.accountId,
      fromDeviceId: req.session!.deviceId,
      envelopeType: "senderkey",
      ciphertext,
      ttlMs: parsed.data.ttlSeconds ? parsed.data.ttlSeconds * 1000 : undefined,
    });
    delivered++;
  }
  res.status(201).json({ fannedOutTo: delivered });
});
