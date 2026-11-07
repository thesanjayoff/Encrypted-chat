import { WS_BASE } from "./config.js";

export interface IncomingMessage {
  id: string;
  fromAccountId: string | null;
  fromDeviceId: string | null;
  envelopeType: string;
  ciphertext: string;
  createdAt: number;
}

export type GatewayEvent =
  | { type: "message"; message: IncomingMessage }
  | { type: "typing"; fromDeviceId: string; isTyping: boolean }
  | { type: "read"; fromDeviceId: string; messageId: string };

type Listener = (event: GatewayEvent) => void;

class Gateway {
  private socket: WebSocket | null = null;
  private listeners = new Set<Listener>();
  private token: string | null = null;
  private reconnectDelay = 1000;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private closedByUser = false;

  connect(token: string): void {
    this.token = token;
    this.closedByUser = false;
    this.open();
  }

  private open(): void {
    if (!this.token) return;
    const socket = new WebSocket(`${WS_BASE}/ws?token=${encodeURIComponent(this.token)}`);
    this.socket = socket;

    socket.onopen = () => {
      this.reconnectDelay = 1000;
    };
    socket.onmessage = (ev) => {
      // A superseded socket (disconnect() followed immediately by a new
      // connect(), as React StrictMode's double-effect does on every dev
      // mount) can still be mid-close when this fires — ignore anything
      // from a socket that isn't the current one, so listeners never see
      // the same push event delivered twice.
      if (this.socket !== socket) return;
      try {
        const data = JSON.parse(ev.data) as GatewayEvent;
        for (const l of this.listeners) l(data);
      } catch {
        /* ignore malformed frames */
      }
    };
    socket.onclose = () => {
      // Same supersession check for reconnects: a stale socket's close must
      // never schedule a reconnect on behalf of the connection that replaced it.
      if (this.socket !== socket) return;
      if (this.closedByUser) return;
      this.reconnectTimer = setTimeout(() => this.open(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30_000);
    };
  }

  disconnect(): void {
    this.closedByUser = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.socket?.close();
    this.socket = null;
  }

  send(payload: unknown): void {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(payload));
    }
  }

  ackMessages(messageIds: string[]): void {
    if (messageIds.length) this.send({ type: "ack", messageIds });
  }

  sendTyping(toDeviceId: string, isTyping: boolean): void {
    this.send({ type: "typing", toDeviceId, isTyping });
  }

  sendReadReceipt(toDeviceId: string, messageId: string): void {
    this.send({ type: "read", toDeviceId, messageId });
  }

  on(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

export const gateway = new Gateway();
