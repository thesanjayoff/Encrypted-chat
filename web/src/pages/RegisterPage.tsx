import type { ReactElement } from "react";
import { useState } from "react";
import { Link } from "react-router-dom";
import AuthCard, { FieldError, inputClass, primaryButtonClass } from "../components/AuthCard.js";
import { register } from "../lib/auth.js";
import { useSession } from "../context/SessionContext.js";
import { loadLocalIdentity } from "../lib/identity.js";

const USERNAME_RE = /^[a-z0-9_]{3,32}$/;

export default function RegisterPage(): ReactElement {
  const { onReady } = useSession();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [usePasscode, setUsePasscode] = useState(false);
  const [passcode, setPasscode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    if (!USERNAME_RE.test(username)) {
      setError("Username must be 3-32 characters: lowercase letters, numbers, underscore.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    if (usePasscode && passcode.length < 4) {
      setError("App-lock passcode must be at least 4 characters.");
      return;
    }
    setBusy(true);
    try {
      await register(username, password, usePasscode ? passcode : null);
      const loaded = await loadLocalIdentity();
      if (loaded) onReady(loaded);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard title="Create an account" subtitle="Your private keys are generated on this device and never sent anywhere.">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Username</label>
          <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} autoComplete="username" />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Password</label>
          <input className={inputClass} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
          <p className="mt-1 text-xs text-slate-400">
            Verified with OPAQUE — the server never sees this password, or anything an attacker could brute-force offline from what it stores.
          </p>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Confirm password</label>
          <input className={inputClass} type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
        </div>
        <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
          <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
            <input type="checkbox" checked={usePasscode} onChange={(e) => setUsePasscode(e.target.checked)} />
            Set an app-lock passcode
          </label>
          <p className="mt-1 text-xs text-slate-400">
            Encrypts everything stored on this device with a key derived from this passcode. Without it, local data is protected only by a
            device-generated key — fine for convenience, not for someone with access to this device.
          </p>
          {usePasscode && (
            <input
              className={inputClass + " mt-2"}
              type="password"
              placeholder="App-lock passcode"
              value={passcode}
              onChange={(e) => setPasscode(e.target.value)}
            />
          )}
        </div>
        <FieldError message={error} />
        <button type="submit" disabled={busy} className={primaryButtonClass}>
          {busy ? "Creating account…" : "Create account"}
        </button>
      </form>
      <p className="mt-4 text-center text-sm text-slate-500 dark:text-slate-400">
        <Link to="/" className="text-brand-600 hover:underline dark:text-brand-400">
          Back
        </Link>
      </p>
    </AuthCard>
  );
}
