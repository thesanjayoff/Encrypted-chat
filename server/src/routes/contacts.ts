import { Router } from "express";
import { z } from "zod";
import { db } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { apiLimiter } from "../middleware/rateLimit.js";

export const contactsRouter = Router();

// Server-side a "contact" is nothing but an (owner, contact) id pair used to
// show the caller their own list back — no display name, no note, no
// anything else. Display names/nicknames live only in each client's local,
// encrypted-at-rest database.

const addSchema = z.object({ username: z.string().min(1) });

contactsRouter.post("/", requireAuth, apiLimiter, (req, res) => {
  const parsed = addSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "invalid request" });
    return;
  }
  const target = db.prepare(`SELECT id FROM accounts WHERE username = ?`).get(parsed.data.username) as { id: string } | undefined;
  if (!target) {
    res.status(404).json({ error: "no such user" });
    return;
  }
  if (target.id === req.session!.accountId) {
    res.status(400).json({ error: "cannot add yourself" });
    return;
  }
  db.prepare(`INSERT OR IGNORE INTO contacts (owner_account_id, contact_account_id, created_at) VALUES (?, ?, ?)`).run(
    req.session!.accountId,
    target.id,
    Date.now(),
  );
  res.status(201).json({ accountId: target.id, username: parsed.data.username });
});

contactsRouter.get("/", requireAuth, apiLimiter, (req, res) => {
  const rows = db
    .prepare(
      `SELECT a.id as accountId, a.username FROM contacts c JOIN accounts a ON a.id = c.contact_account_id WHERE c.owner_account_id = ?`,
    )
    .all(req.session!.accountId);
  res.json({ contacts: rows });
});

contactsRouter.delete("/:accountId", requireAuth, apiLimiter, (req, res) => {
  db.prepare(`DELETE FROM contacts WHERE owner_account_id = ? AND contact_account_id = ?`).run(req.session!.accountId, req.params.accountId);
  res.status(204).end();
});
