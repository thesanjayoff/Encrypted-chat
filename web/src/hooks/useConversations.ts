import { useLiveQuery } from "dexie-react-hooks";
import { db } from "../lib/db.js";
import { readPlaintext } from "../lib/messaging.js";

export interface ConversationSummary {
  id: string; // accountId or groupId
  kind: "contact" | "group";
  title: string;
  verified: boolean;
  lastText: string | null;
  lastAt: number;
}

export function useConversations(): ConversationSummary[] | undefined {
  return useLiveQuery(async () => {
    const [contacts, groups, messages] = await Promise.all([db.contacts.toArray(), db.groups.toArray(), db.messages.toArray()]);

    const lastByConversation = new Map<string, { at: number; text: string | null }>();
    for (const m of messages) {
      const existing = lastByConversation.get(m.conversationId);
      if (existing && existing.at >= m.createdAt) continue;
      let text: string | null = null;
      if (m.deletedForEveryone) {
        text = "This message was deleted";
      } else {
        try {
          const payload = readPlaintext(m);
          text = payload.kind === "text" ? payload.text ?? null : payload.kind === "attachment" ? `📎 ${payload.attachment?.filename ?? "attachment"}` : "System message";
        } catch {
          text = null;
        }
      }
      lastByConversation.set(m.conversationId, { at: m.createdAt, text });
    }

    const list: ConversationSummary[] = [
      ...contacts.map((c) => ({
        id: c.accountId,
        kind: "contact" as const,
        title: c.nickname || c.username,
        verified: c.verified,
        lastText: lastByConversation.get(c.accountId)?.text ?? null,
        lastAt: lastByConversation.get(c.accountId)?.at ?? c.addedAt,
      })),
      ...groups.map((g) => ({
        id: g.groupId,
        kind: "group" as const,
        title: g.name || "Unnamed group",
        verified: true,
        lastText: lastByConversation.get(g.groupId)?.text ?? null,
        lastAt: lastByConversation.get(g.groupId)?.at ?? g.createdAt,
      })),
    ];

    list.sort((a, b) => b.lastAt - a.lastAt);
    return list;
  }, []);
}
