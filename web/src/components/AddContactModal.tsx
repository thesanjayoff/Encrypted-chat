import type { ReactElement } from "react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Modal from "./Modal.js";
import { FieldError, inputClass, primaryButtonClass } from "./AuthCard.js";
import { addContact } from "../lib/contacts.js";

export default function AddContactModal({ onClose }: { onClose: () => void }): ReactElement {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    const name = username.trim().toLowerCase();
    if (!name) return;
    setBusy(true);
    try {
      const contact = await addContact(name);
      onClose();
      navigate(`/chat/contact/${contact.accountId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add contact");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Add contact" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Username</label>
          <input
            className={inputClass}
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
        </div>
        <FieldError message={error} />
        <button type="submit" disabled={busy} className={primaryButtonClass}>
          {busy ? "Adding…" : "Add contact"}
        </button>
      </form>
    </Modal>
  );
}
