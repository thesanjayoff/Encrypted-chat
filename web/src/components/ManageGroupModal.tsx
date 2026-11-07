import type { ReactElement } from "react";
import { useState } from "react";
import { useLiveQuery } from "dexie-react-hooks";
import Modal from "./Modal.js";
import { FieldError, inputClass, primaryButtonClass } from "./AuthCard.js";
import { db, type GroupRow } from "../lib/db.js";
import { api } from "../lib/api.js";
import { rotateAndDistribute } from "../lib/groups.js";
import { useSession } from "../context/SessionContext.js";

export default function ManageGroupModal({ group, onClose }: { group: GroupRow; onClose: () => void }): ReactElement {
  const { identity } = useSession();
  const contacts = useLiveQuery(() => db.contacts.toArray(), []);
  const [addUsername, setAddUsername] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const memberContacts = (contacts ?? []).filter((c) => group.memberAccountIds.includes(c.accountId));

  async function redistribute(newMemberIds: string[]): Promise<void> {
    if (!identity) return;
    const members = (contacts ?? [])
      .filter((c) => newMemberIds.includes(c.accountId))
      .map((c) => ({ accountId: c.accountId, username: c.username }));
    // Every membership change rotates this device's Sender Key and
    // redistributes only to who remains — the mechanism that keeps a
    // removed member from reading anything sent afterward.
    await rotateAndDistribute(identity.identity, identity.accountId, group.groupId, members);
  }

  async function handleAdd(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    const username = addUsername.trim().toLowerCase();
    if (!username) return;
    setBusy(true);
    try {
      const res = await api.post<{ members: string[] }>(`/api/groups/${group.groupId}/members`, { addUsernames: [username] });
      await db.groups.update(group.groupId, { memberAccountIds: res.members });
      await redistribute(res.members);
      setAddUsername("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add member");
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(accountId: string): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<{ members: string[] }>(`/api/groups/${group.groupId}/members`, { removeAccountIds: [accountId] });
      await db.groups.update(group.groupId, { memberAccountIds: res.members });
      await redistribute(res.members);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove member");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={`Members of ${group.name}`} onClose={onClose}>
      <div className="space-y-4">
        <div className="max-h-48 space-y-1 overflow-y-auto">
          {memberContacts.length === 0 && <p className="text-sm text-slate-400">No other members yet.</p>}
          {memberContacts.map((c) => (
            <div key={c.accountId} className="flex items-center justify-between rounded px-2 py-1 text-sm hover:bg-slate-50 dark:hover:bg-slate-800">
              <span>{c.nickname || c.username}</span>
              <button onClick={() => handleRemove(c.accountId)} disabled={busy} className="text-xs text-red-500 hover:underline">
                Remove
              </button>
            </div>
          ))}
          {group.memberAccountIds.length > memberContacts.length + 1 && (
            <p className="px-2 text-xs text-slate-400">
              + {group.memberAccountIds.length - memberContacts.length - 1} more member(s) you haven't added as a contact
            </p>
          )}
        </div>
        <form onSubmit={handleAdd} className="flex gap-2">
          <input
            className={inputClass}
            placeholder="Add by username"
            value={addUsername}
            onChange={(e) => setAddUsername(e.target.value)}
          />
          <button type="submit" disabled={busy} className={primaryButtonClass + " w-auto px-4"}>
            Add
          </button>
        </form>
        <FieldError message={error} />
      </div>
    </Modal>
  );
}
