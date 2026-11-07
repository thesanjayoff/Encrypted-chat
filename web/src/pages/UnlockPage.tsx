import type { ReactElement } from "react";
import { useState } from "react";
import AuthCard, { FieldError, inputClass, primaryButtonClass, secondaryButtonClass } from "../components/AuthCard.js";
import { unlockOnly, clearPersistedSession } from "../lib/auth.js";
import { loadLocalIdentity } from "../lib/identity.js";
import { useSession } from "../context/SessionContext.js";

export default function UnlockPage(): ReactElement {
  const { onReady, refreshStatus } = useSession();
  const [passcode, setPasscode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await unlockOnly(passcode);
      const loaded = await loadLocalIdentity();
      if (loaded) onReady(loaded);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unlock failed");
    } finally {
      setBusy(false);
    }
  }

  function switchToFullLogin(): void {
    clearPersistedSession();
    refreshStatus();
  }

  return (
    <AuthCard title="Enter your passcode" subtitle="Unlocks this device's local, encrypted data for your current session.">
      <form onSubmit={handleSubmit} className="space-y-4">
        <input className={inputClass} type="password" value={passcode} onChange={(e) => setPasscode(e.target.value)} autoFocus />
        <FieldError message={error} />
        <button type="submit" disabled={busy} className={primaryButtonClass}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
      <button onClick={switchToFullLogin} className={secondaryButtonClass + " mt-3"}>
        Log in with password instead
      </button>
    </AuthCard>
  );
}
