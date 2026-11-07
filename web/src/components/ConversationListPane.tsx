import type { ReactElement } from "react";
import { useState } from "react";
import { NavLink, useParams } from "react-router-dom";
import { useConversations } from "../hooks/useConversations.js";
import AddContactModal from "./AddContactModal.js";
import NewGroupModal from "./NewGroupModal.js";

function timeLabel(ts: number): string {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

export default function ConversationListPane(): ReactElement {
  const conversations = useConversations();
  const { id: activeId } = useParams();
  const [showAddContact, setShowAddContact] = useState(false);
  const [showNewGroup, setShowNewGroup] = useState(false);

  return (
    <div className="flex h-full w-80 flex-col border-r border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center justify-between border-b border-slate-200 p-4 dark:border-slate-800">
        <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Chats</h1>
        <div className="flex gap-1">
          <button
            onClick={() => setShowNewGroup(true)}
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
            title="New group"
          >
            <GroupIcon />
          </button>
          <button
            onClick={() => setShowAddContact(true)}
            className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
            title="Add contact"
          >
            <PlusIcon />
          </button>
        </div>
      </div>
      <div className="scrollbar-thin flex-1 overflow-y-auto">
        {conversations?.length === 0 && (
          <p className="p-6 text-center text-sm text-slate-400">No conversations yet. Add a contact to get started.</p>
        )}
        {conversations?.map((c) => (
          <NavLink
            key={c.id}
            to={`/chat/${c.kind}/${c.id}`}
            className={`flex items-center gap-3 border-b border-slate-100 px-4 py-3 transition hover:bg-slate-50 dark:border-slate-800/60 dark:hover:bg-slate-800/60 ${
              activeId === c.id ? "bg-brand-50 dark:bg-brand-900/20" : ""
            }`}
          >
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-200 text-sm font-medium text-slate-600 dark:bg-slate-700 dark:text-slate-200">
              {c.kind === "group" ? <GroupIcon className="h-5 w-5" /> : c.title.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">{c.title}</span>
                <span className="shrink-0 text-xs text-slate-400">{timeLabel(c.lastAt)}</span>
              </div>
              <div className="flex items-center gap-1">
                {c.kind === "contact" && c.verified && (
                  <span className="text-xs text-emerald-600 dark:text-emerald-400" title="Safety number verified">
                    ✓
                  </span>
                )}
                <p className="truncate text-xs text-slate-500 dark:text-slate-400">{c.lastText ?? "No messages yet"}</p>
              </div>
            </div>
          </NavLink>
        ))}
      </div>
      {showAddContact && <AddContactModal onClose={() => setShowAddContact(false)} />}
      {showNewGroup && <NewGroupModal onClose={() => setShowNewGroup(false)} />}
    </div>
  );
}

function PlusIcon(): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
      <path d="M12 5v14M5 12h14" />
    </svg>
  );
}
function GroupIcon({ className = "h-5 w-5" }: { className?: string }): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}
