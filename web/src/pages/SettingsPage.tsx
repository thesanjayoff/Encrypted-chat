import type { ReactElement } from "react";
import { useEffect, useState } from "react";
import { useSession } from "../context/SessionContext.js";
import { useTheme } from "../hooks/useTheme.js";
import { vault } from "../lib/vault.js";

export default function SettingsPage(): ReactElement {
  const { identity } = useSession();
  const { theme, setTheme } = useTheme();
  const [hasPasscode, setHasPasscode] = useState(false);

  useEffect(() => {
    void vault.hasPasscode().then(setHasPasscode);
  }, []);

  return (
    <div className="h-full max-w-xl overflow-y-auto p-8">
      <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Settings</h1>

      <section className="mt-6">
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Account</h2>
        <div className="mt-2 rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-800">
          <p className="text-slate-900 dark:text-slate-100">@{identity?.username}</p>
          <p className="mt-1 text-xs text-slate-400">Account id: {identity?.accountId}</p>
          <p className="text-xs text-slate-400">This device id: {identity?.deviceId}</p>
        </div>
      </section>

      <section className="mt-6">
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Appearance</h2>
        <div className="mt-2 flex gap-2">
          {(["light", "dark", "system"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTheme(t)}
              className={`rounded-lg border px-3 py-1.5 text-sm capitalize transition ${
                theme === t
                  ? "border-brand-500 bg-brand-50 text-brand-700 dark:bg-brand-900/30 dark:text-brand-300"
                  : "border-slate-300 text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </section>

      <section className="mt-6">
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">App lock</h2>
        <div className="mt-2 rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-800">
          <p className="text-slate-900 dark:text-slate-100">{hasPasscode ? "On" : "Off"}</p>
          <p className="mt-1 text-xs text-slate-400">
            {hasPasscode
              ? "Your local data is encrypted with a key derived from your app-lock passcode."
              : "Your local data is encrypted with a device-generated key, not a passcode — fine for convenience, but anyone with access to this unlocked browser profile can read it. This was chosen at registration; changing it later isn't supported in this version."}
          </p>
        </div>
      </section>

      <section className="mt-6">
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Privacy &amp; security notes</h2>
        <ul className="mt-2 list-inside list-disc space-y-1 text-xs text-slate-500 dark:text-slate-400">
          <li>Messages are end-to-end encrypted with the Double Ratchet; the server only ever stores and relays ciphertext.</li>
          <li>Ratchet headers (a counter and a rotating public key) travel in plaintext alongside each message — the server can see message cadence, even though it can't read content.</li>
          <li>Being online and typing are visible to whoever you're chatting with as presence metadata whenever you're connected — see the project's THREAT_MODEL.md for the full list of what the server can and can't see.</li>
          <li>This is a learning / portfolio project and has not been professionally audited.</li>
        </ul>
      </section>
    </div>
  );
}
