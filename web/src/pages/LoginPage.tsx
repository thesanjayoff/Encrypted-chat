import type { ReactElement } from "react";
import { useEffect, useState } from "react";
import AuthCard, { FieldError, inputClass, primaryButtonClass } from "../components/AuthCard.js";
import { login } from "../lib/auth.js";
import { loadLocalIdentity } from "../lib/identity.js";
import { useSession } from "../context/SessionContext.js";
import { vault } from "../lib/vault.js";

export default function LoginPage(): ReactElement {
  const { onReady } = useSession();
  const [password, setPassword] = useState("");
  const [passcode, setPasscode] = useState("");
  const [needsPasscode, setNeedsPasscode] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void vault.hasPasscode().then(setNeedsPasscode);
  }, []);

  async function handleSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(password, needsPasscode ? passcode : null);
      const loaded = await loadLocalIdentity();
      if (loaded) onReady(loaded);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard title="Log in" subtitle="This device already has a local identity for this account.">
      <form onSubmit={handleSubmit} className="space-y-4">
        {needsPasscode && (
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">App-lock passcode</label>
            <input className={inputClass} type="password" value={passcode} onChange={(e) => setPasscode(e.target.value)} autoFocus />
          </div>
        )}
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Password</label>
          <input
            className={inputClass}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            autoFocus={!needsPasscode}
          />
        </div>
        <FieldError message={error} />
        <button type="submit" disabled={busy} className={primaryButtonClass}>
          {busy ? "Logging in…" : "Log in"}
        </button>
      </form>
    </AuthCard>
  );
}
