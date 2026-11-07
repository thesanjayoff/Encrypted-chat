import type { Request, Response, NextFunction } from "express";
import { resolveSession, type SessionInfo } from "../sessions.js";

declare module "express-serve-static-core" {
  interface Request {
    session?: SessionInfo;
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : null;
  if (!token) {
    res.status(401).json({ error: "missing bearer token" });
    return;
  }
  const session = resolveSession(token);
  if (!session) {
    res.status(401).json({ error: "invalid or expired session" });
    return;
  }
  req.session = session;
  next();
}
