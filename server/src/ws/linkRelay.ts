import type { WebSocket } from "ws";
import { db } from "../db.js";

/**
 * Pure byte relay for device linking. The server never parses what passes
 * through here — it just forwards whatever either side of a given
 * `linkToken` sends to the other side. The two devices run their own X25519
 * handshake (and then AEAD-encrypt everything, including the account's
 * identity private key material) over this pipe; the server is a dumb wire.
 */
const channels = new Map<string, Set<WebSocket>>();

export function handleLinkSocket(socket: WebSocket, linkToken: string): void {
  const row = db.prepare(`SELECT expires_at, used FROM device_link_sessions WHERE token = ?`).get(linkToken) as
    | { expires_at: number; used: number }
    | undefined;
  if (!row || row.expires_at < Date.now()) {
    socket.close(4001, "invalid or expired link token");
    return;
  }

  if (!channels.has(linkToken)) channels.set(linkToken, new Set());
  const peers = channels.get(linkToken)!;
  if (peers.size >= 2) {
    socket.close(4002, "link channel already full");
    return;
  }
  peers.add(socket);

  socket.on("message", (data) => {
    for (const peer of peers) {
      if (peer !== socket && peer.readyState === peer.OPEN) peer.send(data.toString());
    }
  });

  const cleanup = () => {
    peers.delete(socket);
    if (peers.size === 0) channels.delete(linkToken);
  };
  socket.on("close", cleanup);
  socket.on("error", cleanup);
}
