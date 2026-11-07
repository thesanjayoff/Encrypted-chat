import type { ReactElement } from "react";
import { useState } from "react";
import { Link } from "react-router-dom";
import AuthCard, { FieldError, inputClass, primaryButtonClass } from "../components/AuthCard.js";
import { joinDeviceLink } from "../lib/deviceLink.js";
import { persistSession } from "../lib/auth.js";
import { setSessionToken } from "../lib/api.js";
import { loadLocalIdentity } from "../lib/identity.js";
import { useSession } from "../context/SessionContext.js";

export default function LinkDevicePage(): ReactElement {
  const { onReady } = useSession();
  const [linkToken, setLinkToken] = useState("");
  const [usePasscode, setUsePasscode] = useState(false);
  const [passcode, setPasscode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    if (!linkToken.trim()) {
      setError("Paste the code shown on your other device.");
      return;
    }
    setBusy(true);
    try {
      const result = await joinDeviceLink(linkToken.trim(), usePasscode ? passcode : null);
      setSessionToken(result.sessionToken);
      const loaded = await loadLocalIdentity();
      if (loaded) {
        persistSession({ accountId: loaded.accountId, username: loaded.username, deviceId: loaded.deviceId, sessionToken: result.sessionToken });
        onReady(loaded);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Linking failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard title="Link this device" subtitle="On your other, already-logged-in device, open Settings → Devices → Link a new device, and paste the code it shows here.">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-slate-600 dark:text-slate-400">Link code</label>
          <textarea
            className={inputClass + " h-20 font-mono text-xs"}
            value={linkToken}
            onChange={(e) => setLinkToken(e.target.value)}
            placeholder="Paste the link code here"
          />
        </div>
        <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-700">
          <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
            <input type="checkbox" checked={usePasscode} onChange={(e) => setUsePasscode(e.target.checked)} />
            Set an app-lock passcode for this device
          </label>
          {usePasscode && (
            <input className={inputClass + " mt-2"} type="password" value={passcode} onChange={(e) => setPasscode(e.target.value)} />
          )}
        </div>
        <FieldError message={error} />
        <button type="submit" disabled={busy} className={primaryButtonClass}>
          {busy ? "Linking…" : "Link device"}
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
