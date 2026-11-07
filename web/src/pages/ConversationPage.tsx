import type { ReactElement } from "react";
import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useLiveQuery } from "dexie-react-hooks";
import { db, type ContactRow } from "../lib/db.js";
import { useSession } from "../context/SessionContext.js";
import { sendToContact, requestDeleteForEveryone, type PlaintextPayload } from "../lib/messaging.js";
import { sendGroupMessage, requestGroupDeleteForEveryone } from "../lib/groups.js";
import { encryptAndUploadAttachment, MAX_ATTACHMENT_BYTES } from "../lib/attachments.js";
import MessageBubble from "../components/MessageBubble.js";
import SafetyNumberModal from "../components/SafetyNumberModal.js";
import ManageGroupModal from "../components/ManageGroupModal.js";
import { FieldError } from "../components/AuthCard.js";

const DISAPPEARING_OPTIONS = [
  { label: "Off", value: 0 },
  { label: "1 hour", value: 3600 },
  { label: "1 day", value: 86400 },
  { label: "1 week", value: 604800 },
];

export default function ConversationPage(): ReactElement {
  const { kind, id } = useParams<{ kind: string; id: string }>();
  const { identity, inboxVersion, typingFrom } = useSession();
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSafety, setShowSafety] = useState(false);
  const [showManage, setShowManage] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const isContact = kind === "contact";
  const isGroup = kind === "group";

  const contact = useLiveQuery(() => (isContact && id ? db.contacts.get(id) : undefined), [isContact, id]);
  const group = useLiveQuery(() => (isGroup && id ? db.groups.get(id) : undefined), [isGroup, id]);

  const messages = useLiveQuery(async () => {
    if (!id) return [];
    const rows = await db.messages.where("conversationId").equals(id).sortBy("createdAt");
    return rows.filter((r) => !(r.expiresAt && r.expiresAt < Date.now()));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, inboxVersion]);

  const contactMembers = useLiveQuery(
    () => (isGroup && group ? db.contacts.toArray() : Promise.resolve<ContactRow[]>([])),
    [isGroup, group],
  );

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages?.length]);

  if (!id || (!isContact && !isGroup)) return <div />;

  const title = isContact ? contact?.nickname || contact?.username || "" : group?.name || "";
  const disappearingSeconds = isContact ? contact?.disappearingSeconds ?? 0 : group?.disappearingSeconds ?? 0;
  const anyTyping = typingFrom.size > 0; // device-level, not contact-scoped — see README limitations

  function senderLabelFor(senderAccountId: string): string | undefined {
    if (!isGroup) return undefined;
    if (senderAccountId === identity?.accountId) return undefined;
    return contactMembers?.find((c) => c.accountId === senderAccountId)?.username ?? senderAccountId.slice(0, 8);
  }

  async function setDisappearing(seconds: number): Promise<void> {
    if (isContact && contact) await db.contacts.update(contact.accountId, { disappearingSeconds: seconds || undefined });
    if (isGroup && group) await db.groups.update(group.groupId, { disappearingSeconds: seconds || undefined });
  }

  async function handleSend(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    if (!identity || !text.trim()) return;
    setSending(true);
    setError(null);
    try {
      const payload: PlaintextPayload = { kind: "text", text: text.trim(), sentAt: Date.now(), disappearingSeconds: disappearingSeconds || undefined };
      if (isContact && contact) await sendToContact(identity.identity, identity.accountId, contact, payload);
      else if (isGroup && group) await sendGroupMessage(identity.accountId, group.groupId, payload);
      setText("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send message");
    } finally {
      setSending(false);
    }
  }

  async function handleAttachment(e: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file || !identity) return;
    setSending(true);
    setError(null);
    try {
      const attachment = await encryptAndUploadAttachment(file);
      const payload: PlaintextPayload = { kind: "attachment", attachment, sentAt: Date.now(), disappearingSeconds: disappearingSeconds || undefined };
      if (isContact && contact) await sendToContact(identity.identity, identity.accountId, contact, payload);
      else if (isGroup && group) await sendGroupMessage(identity.accountId, group.groupId, payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send attachment");
    } finally {
      setSending(false);
    }
  }

  async function handleDelete(messageId: string): Promise<void> {
    if (!identity) return;
    if (isContact && contact) await requestDeleteForEveryone(identity.identity, identity.accountId, contact, messageId);
    else if (isGroup && group) await requestGroupDeleteForEveryone(identity.accountId, group.groupId, messageId);
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-slate-200 bg-white px-5 py-3 dark:border-slate-800 dark:bg-slate-900">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          <p className="text-xs text-slate-400">
            {isContact ? (contact?.verified ? "Verified · End-to-end encrypted" : "End-to-end encrypted · not yet verified") : `${group?.memberAccountIds.length ?? 0} members · end-to-end encrypted`}
            {anyTyping && " · typing…"}
          </p>
        </div>
        <div className="flex gap-2">
          <select
            className="rounded-lg border border-slate-300 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-800"
            value={disappearingSeconds}
            onChange={(e) => void setDisappearing(Number(e.target.value))}
            title="Disappearing messages"
          >
            {DISAPPEARING_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          {isContact && (
            <button
              onClick={() => setShowSafety(true)}
              className="rounded-lg border border-slate-300 px-3 py-1 text-xs text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Safety number
            </button>
          )}
          {isGroup && (
            <button
              onClick={() => setShowManage(true)}
              className="rounded-lg border border-slate-300 px-3 py-1 text-xs text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Members
            </button>
          )}
        </div>
      </div>

      <div className="scrollbar-thin flex-1 space-y-2 overflow-y-auto bg-slate-50 px-5 py-4 dark:bg-slate-950">
        {messages?.map((row) => (
          <MessageBubble key={row.id} row={row} senderLabel={senderLabelFor(row.senderAccountId)} onDeleteForEveryone={handleDelete} />
        ))}
        <div ref={bottomRef} />
      </div>

      <form onSubmit={handleSend} className="flex items-end gap-2 border-t border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        <input ref={fileInputRef} type="file" className="hidden" onChange={handleAttachment} />
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          title={`Attach a file (max ${Math.floor(MAX_ATTACHMENT_BYTES / 1024 / 1024)} MB)`}
          className="shrink-0 rounded-lg p-2 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <PaperclipIcon />
        </button>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void handleSend(e);
            }
          }}
          placeholder="Type a message…"
          rows={1}
          className="max-h-32 flex-1 resize-none rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
        />
        <button
          type="submit"
          disabled={sending || !text.trim()}
          className="shrink-0 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
        >
          Send
        </button>
      </form>
      {error && <div className="px-5 pb-2"><FieldError message={error} /></div>}

      {showSafety && contact && <SafetyNumberModal contact={contact} onClose={() => setShowSafety(false)} />}
      {showManage && group && <ManageGroupModal group={group} onClose={() => setShowManage(false)} />}
    </div>
  );
}

function PaperclipIcon(): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
      <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
    </svg>
  );
}
