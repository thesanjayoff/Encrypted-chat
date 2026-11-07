import type { ReactElement } from "react";
import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { listDevices, revokeDevice, startDeviceLink, type DeviceInfo } from "../lib/devices.js";
import { hostDeviceLink } from "../lib/deviceLink.js";
import { useSession } from "../context/SessionContext.js";
import { primaryButtonClass, secondaryButtonClass, FieldError } from "../components/AuthCard.js";

export default function DevicesPage(): ReactElement {
  const { identity } = useSession();
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [linking, setLinking] = useState<{ token: string; qr: string | null; status: "waiting" | "done" | "error" } | null>(null);

  async function refresh(): Promise<void> {
    try {
      setDevices(await listDevices());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load devices");
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function handleRevoke(deviceId: string): Promise<void> {
    await revokeDevice(deviceId);
    await refresh();
  }

  async function handleStartLink(): Promise<void> {
    if (!identity) return;
    setError(null);
    try {
      const { linkToken } = await startDeviceLink();
      const qr = await QRCode.toDataURL(linkToken, { margin: 1, width: 220 }).catch(() => null);
      setLinking({ token: linkToken, qr, status: "waiting" });
      await hostDeviceLink(identity.identity, identity.username, linkToken);
      setLinking((prev) => (prev ? { ...prev, status: "done" } : prev));
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Linking failed");
      setLinking((prev) => (prev ? { ...prev, status: "error" } : prev));
    }
  }

  return (
    <div className="h-full overflow-y-auto p-8">
      <h1 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Devices</h1>
      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Devices with access to your account's identity and messages.</p>

      <div className="mt-6 space-y-2">
        {devices.map((d) => (
          <div
            key={d.id}
            className="flex items-center justify-between rounded-lg border border-slate-200 p-3 dark:border-slate-800"
          >
            <div>
              <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                {d.label || "Unnamed device"} {d.is_primary ? <span className="text-xs text-slate-400">(primary)</span> : null}
              </p>
              <p className="text-xs text-slate-400">
                Added {new Date(d.created_at).toLocaleDateString()}
                {d.last_seen_at ? ` · last seen ${new Date(d.last_seen_at).toLocaleString()}` : ""}
              </p>
            </div>
            {d.id !== identity?.deviceId && (
              <button onClick={() => handleRevoke(d.id)} className="text-xs text-red-500 hover:underline">
                Remove
              </button>
            )}
          </div>
        ))}
      </div>

      <FieldError message={error} />

      <div className="mt-8 max-w-sm rounded-xl border border-slate-200 p-4 dark:border-slate-800">
        <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Link a new device</h2>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          Open the "link this device" screen on your new device and scan the code, or paste it in manually.
        </p>
        {!linking ? (
          <button onClick={handleStartLink} className={primaryButtonClass + " mt-3"}>
            Show link code
          </button>
        ) : (
          <div className="mt-3 space-y-3">
            {linking.qr && <img src={linking.qr} alt="Device link QR code" className="mx-auto rounded-lg" />}
            <p className="break-all rounded-lg bg-slate-100 p-2 font-mono text-xs dark:bg-slate-800">{linking.token}</p>
            {linking.status === "waiting" && <p className="text-xs text-slate-400">Waiting for the new device…</p>}
            {linking.status === "done" && <p className="text-xs text-emerald-600 dark:text-emerald-400">Device linked successfully.</p>}
            {linking.status === "error" && <p className="text-xs text-red-500">Linking failed or expired.</p>}
            <button onClick={() => setLinking(null)} className={secondaryButtonClass}>
              Close
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
