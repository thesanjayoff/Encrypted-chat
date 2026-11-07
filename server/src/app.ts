import express from "express";
import cors from "cors";
import { CORS_ORIGIN } from "./env.js";
import { authRouter } from "./routes/auth.js";
import { keysRouter } from "./routes/keys.js";
import { messagesRouter } from "./routes/messages.js";
import { contactsRouter } from "./routes/contacts.js";
import { groupsRouter } from "./routes/groups.js";
import { attachmentsRouter } from "./routes/attachments.js";
import { devicesRouter } from "./routes/devices.js";

export function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(cors({ origin: CORS_ORIGIN }));
  // Attachments route installs its own express.raw() parser for its one
  // binary route; everything else is JSON.
  app.use((req, res, next) => {
    if (req.path.startsWith("/api/attachments") && req.method === "POST") return next();
    express.json({ limit: "1mb" })(req, res, next);
  });

  app.get("/health", (_req, res) => res.json({ ok: true }));

  app.use("/api/auth", authRouter);
  app.use("/api/keys", keysRouter);
  app.use("/api/messages", messagesRouter);
  app.use("/api/contacts", contactsRouter);
  app.use("/api/groups", groupsRouter);
  app.use("/api/attachments", attachmentsRouter);
  app.use("/api/devices", devicesRouter);

  // Never let an error handler leak internals (and never log bodies —
  // they may contain ciphertext, which we also just don't need to see).
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error("[error]", err instanceof Error ? err.message : err);
    res.status(500).json({ error: "internal error" });
  });

  return app;
}
