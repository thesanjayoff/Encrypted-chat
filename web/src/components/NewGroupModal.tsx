import type { ReactElement } from "react";
import { useState } from "react";
import { useLiveQuery } from "dexie-react-hooks";
import { useNavigate } from "react-router-dom";
import Modal from "./Modal.js";
import { FieldError, inputClass, primaryButtonClass } from "./AuthCard.js";
import { db } from "../lib/db.js";
import { createGroup } from "../lib/groups.js";
import { useSession } from "../context/SessionContext.js";

export default function NewGroupModal({ onClose }: { onClose: () => void }): ReactElement {
  const { identity } = useSession();
  const navigate = useNavigate();
  const contacts = useLiveQuery(() => db.contacts.toArray(), []);
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function toggle(accountId: string): void {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(accountId)) next.delete(accountId);
      else next.add(accountId);
      return next;
    });
  }

  async function handleSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    if (!identity) return;
    if (!name.trim()) {
      setError("Give the group a name.");
      return;
    }
    if (selected.size === 0) {
      setError("Pick at least one contact.");
      return;
    }
    setBusy(true);
    try {
      const members = (contacts ?? []).filter((c) => selected.has(c.accountId)).map((c) => ({ accountId: c.accountId, username: c.username }));
      const group = await createGroup(identity.identity, identity.accountId, name.trim(), members);
      onClose();
      navigate(`/chat/group/${group.groupId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create group");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="New group" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Group name</label>
          <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          <p className="mt-1 text-xs text-slate-400">Only members ever see this name — the server never stores it.</p>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Members</label>
          <div className="max-h-48 space-y-1 overflow-y-auto rounded-lg border border-slate-200 p-2 dark:border-slate-700">
            {(contacts ?? []).length === 0 && <p className="p-2 text-sm text-slate-400">Add some contacts first.</p>}
            {(contacts ?? []).map((c) => (
              <label key={c.accountId} className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-slate-50 dark:hover:bg-slate-800">
                <input type="checkbox" checked={selected.has(c.accountId)} onChange={() => toggle(c.accountId)} />
                {c.nickname || c.username}
              </label>
            ))}
          </div>
        </div>
        <FieldError message={error} />
        <button type="submit" disabled={busy} className={primaryButtonClass}>
          {busy ? "Creating…" : "Create group"}
        </button>
      </form>
    </Modal>
  );
}
