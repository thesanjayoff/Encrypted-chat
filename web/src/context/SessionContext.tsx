import type { ReactElement } from "react";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { vault } from "../lib/vault.js";
import { db } from "../lib/db.js";
import { hasLocalIdentity, loadLocalIdentity, replenishPreKeysIfNeeded, type LoadedIdentity } from "../lib/identity.js";
import { loadPersistedSession, clearPersistedSession } from "../lib/auth.js";
import { gateway, type GatewayEvent, type IncomingMessage } from "../lib/ws.js";
import { api, setSessionToken } from "../lib/api.js";
import { receiveMessage } from "../lib/messaging.js";
import { handleDistribution, handleGroupMessage, handleMembershipChanged } from "../lib/groups.js";

export type SessionStatus = "loading" | "no-identity" | "needs-unlock" | "needs-login" | "ready";

interface SessionContextValue {
  status: SessionStatus;
  identity: LoadedIdentity | null;
  /** Bumped on every inbound message so views can refetch; prefer
   * dexie-react-hooks' useLiveQuery for data that's already reactive, this
   * is only for cross-cutting things like "a new conversation appeared." */
  inboxVersion: number;
  typingFrom: Set<string>;
  onReady: (identity: LoadedIdentity) => void;
  logout: () => void;
  refreshStatus: () => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within SessionProvider");
  return ctx;
}

export function SessionProvider({ children }: { children: ReactNode }): ReactElement {
  const [status, setStatus] = useState<SessionStatus>("loading");
  const [identity, setIdentity] = useState<LoadedIdentity | null>(null);
  const [inboxVersion, setInboxVersion] = useState(0);
  const [typingFrom, setTypingFrom] = useState<Set<string>>(new Set());
  const identityRef = useRef<LoadedIdentity | null>(null);

  const computeStatus = useCallback(async (): Promise<void> => {
    const hasId = await hasLocalIdentity();
    if (!hasId) {
      setStatus("no-identity");
      return;
    }
    const persisted = loadPersistedSession();
    const autoUnlocked = await vault.tryAutoUnlock();
    if (autoUnlocked && persisted) {
      setSessionToken(persisted.sessionToken);
      const loaded = await loadLocalIdentity();
      identityRef.current = loaded;
      setIdentity(loaded);
      setStatus("ready");
      return;
    }
    if (!autoUnlocked && persisted) {
      setStatus("needs-unlock");
      return;
    }
    setStatus("needs-login");
  }, []);

  useEffect(() => {
    void computeStatus();
  }, [computeStatus]);

  const onReady = useCallback((loaded: LoadedIdentity): void => {
    identityRef.current = loaded;
    setIdentity(loaded);
    setStatus("ready");
  }, []);

  const logout = useCallback((): void => {
    gateway.disconnect();
    vault.lock();
    clearPersistedSession();
    identityRef.current = null;
    setIdentity(null);
    setStatus("needs-login");
  }, []);

  const refreshStatus = useCallback((): void => {
    void computeStatus();
  }, [computeStatus]);

  // Gateway wiring: connect once we're ready, route every inbound event to
  // the right decrypt handler, then ack so the server can drop its queued
  // copy — this is the one place that ties messaging.ts/groups.ts to the
  // live transport.
  useEffect(() => {
    if (status !== "ready" || !identity) return;
    const persisted = loadPersistedSession();
    if (!persisted) return;
    gateway.connect(persisted.sessionToken);

    void replenishPreKeysIfNeeded(identity.identity.signing.privateKey);

    const off = gateway.on((event: GatewayEvent) => {
      void handleEvent(event);
    });

    async function handleEvent(event: GatewayEvent): Promise<void> {
      if (event.type === "typing") {
        setTypingFrom((prev) => {
          const next = new Set(prev);
          if (event.isTyping) next.add(event.fromDeviceId);
          else next.delete(event.fromDeviceId);
          return next;
        });
        return;
      }
      if (event.type === "read") return; // no read-receipt UI yet; see README limitations
      if (event.type !== "message" || !identityRef.current) return;

      const kp = identityRef.current.identity;
      switch (event.message.envelopeType) {
        case "prekey":
        case "ratchet":
          await receiveMessage(kp, event);
          break;
        case "senderkey-distribution":
          await handleDistribution(kp, event.message);
          break;
        case "senderkey":
          await handleGroupMessage(event);
          break;
        case "control":
          await handleMembershipChanged(event.message);
          break;
      }
      gateway.ackMessages([event.message.id]);
      setInboxVersion((v) => v + 1);
    }

    // Catch-up poll for anything missed while this tab wasn't open — the
    // WebSocket push only covers what's sent while we're connected.
    void api.get<{ messages: IncomingMessage[] }>("/api/messages").then(async (res) => {
      for (const message of res.messages) {
        await handleEvent({ type: "message", message });
      }
    });

    // Disappearing messages are enforced client-side only (per the spec's
    // design — there's no way to force a peer's client to delete anything):
    // sweep rows past their expiry out of this device's own local view.
    const purgeTimer = setInterval(() => {
      void db.messages.where("expiresAt").below(Date.now()).delete().then((count) => {
        if (count > 0) setInboxVersion((v) => v + 1);
      });
    }, 5000);

    return () => {
      off();
      gateway.disconnect();
      clearInterval(purgeTimer);
    };
  }, [status, identity]);

  const value: SessionContextValue = { status, identity, inboxVersion, typingFrom, onReady, logout, refreshStatus };
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}
