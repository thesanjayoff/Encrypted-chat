import type { WebSocket } from "ws";
import { z } from "zod";
import { db } from "../db.js";
import { resolveSession } from "../sessions.js";
import { registerConnection, unregisterConnection, getConnections } from "../deviceRegistry.js";
import { serializeRow, type MessageRow } from "../deliver.js";

const clientMessageSchema = z.union([
  z.object({ type: z.literal("ack"), messageIds: z.array(z.string().uuid()).min(1).max(500) }),
  z.object({ type: z.literal("typing"), toDeviceId: z.string().uuid(), isTyping: z.boolean() }),
  z.object({ type: z.literal("read"), toDeviceId: z.string().uuid(), messageId: z.string().uuid() }),
]);

export function handleGatewaySocket(socket: WebSocket, token: string | null): void {
  if (!token) {
    socket.close(4001, "missing token");
    return;
  }
  const session = resolveSession(token);
  if (!session) {
    socket.close(4001, "invalid or expired session");
    return;
  }

  registerConnection(session.deviceId, socket);
  flushQueue(session.deviceId, socket);

  socket.on("message", (data) => {
    let parsed;
    try {
      parsed = clientMessageSchema.safeParse(JSON.parse(data.toString()));
    } catch {
      return;
    }
    if (!parsed.success) return;

    switch (parsed.data.type) {
      case "ack": {
        const del = db.prepare(`DELETE FROM messages WHERE id = ? AND to_device_id = ?`);
        for (const id of parsed.data.messageIds) del.run(id, session.deviceId);
        break;
      }
      case "typing": {
        // Ephemeral, never persisted, best-effort — dropped if the peer is
        // offline. This (and "read", below) is the metadata leak the
        // threat model calls out: both parties' online presence and
        // activity timing are visible to the server as a side effect of
        // relaying this, regardless of payload content.
        relay(parsed.data.toDeviceId, { type: "typing", fromDeviceId: session.deviceId, isTyping: parsed.data.isTyping });
        break;
      }
      case "read": {
        relay(parsed.data.toDeviceId, { type: "read", fromDeviceId: session.deviceId, messageId: parsed.data.messageId });
        break;
      }
    }
  });

  const cleanup = () => unregisterConnection(session.deviceId, socket);
  socket.on("close", cleanup);
  socket.on("error", cleanup);
}

function relay(toDeviceId: string, payload: unknown) {
  const data = JSON.stringify(payload);
  for (const sock of getConnections(toDeviceId)) {
    try {
      sock.send(data);
    } catch {
      /* best effort */
    }
  }
}

function flushQueue(deviceId: string, socket: WebSocket) {
  const rows = db.prepare(`SELECT * FROM messages WHERE to_device_id = ? ORDER BY created_at ASC LIMIT 500`).all(deviceId) as MessageRow[];
  for (const row of rows) {
    try {
      socket.send(JSON.stringify({ type: "message", message: serializeRow(row) }));
    } catch {
      break;
    }
  }
}
