import type { WebSocket } from "ws";

/** In-memory map of which devices currently have a live WebSocket, so a
 * freshly-sent message can be pushed immediately. The database queue (not
 * this map) is the durable source of truth — if a device isn't here, the
 * message just waits in `messages` until the device polls or reconnects. */
const connections = new Map<string, Set<WebSocket>>();

export function registerConnection(deviceId: string, socket: WebSocket): void {
  if (!connections.has(deviceId)) connections.set(deviceId, new Set());
  connections.get(deviceId)!.add(socket);
}

export function unregisterConnection(deviceId: string, socket: WebSocket): void {
  connections.get(deviceId)?.delete(socket);
  if (connections.get(deviceId)?.size === 0) connections.delete(deviceId);
}

export function getConnections(deviceId: string): WebSocket[] {
  return [...(connections.get(deviceId) ?? [])];
}

export function isOnline(deviceId: string): boolean {
  return (connections.get(deviceId)?.size ?? 0) > 0;
}
