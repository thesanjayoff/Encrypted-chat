import type { ReactElement } from "react";
import { useEffect, useState } from "react";
import QRCode from "qrcode";
import Modal from "./Modal.js";
import { primaryButtonClass, secondaryButtonClass } from "./AuthCard.js";
import { safetyNumberFor, setContactVerified, checkForKeyChange, acceptKeyChange } from "../lib/contacts.js";
import { useSession } from "../context/SessionContext.js";
import type { ContactRow } from "../lib/db.js";

export default function SafetyNumberModal({ contact, onClose }: { contact: ContactRow; onClose: () => void }): ReactElement {
  const { identity } = useSession();
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [keyChange, setKeyChange] = useState<{ newSigningKey: string; newDhKey: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const safetyNumber = identity ? safetyNumberFor(identity.identity, contact) : "";

  useEffect(() => {
    if (!safetyNumber) return;
    QRCode.toDataURL(safetyNumber.replace(/ /g, ""), { margin: 1, width: 220 }).then(setQrDataUrl).catch(() => setQrDataUrl(null));
  }, [safetyNumber]);

  async function handleCheck(): Promise<void> {
    setChecking(true);
    setError(null);
    try {
      const result = await checkForKeyChange(contact);
      if (result.changed && result.newSigningKey && result.newDhKey) {
        setKeyChange({ newSigningKey: result.newSigningKey, newDhKey: result.newDhKey });
      } else {
        setError("No change — this contact's key still matches what you verified.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not check for a key change");
    } finally {
      setChecking(false);
    }
  }

  async function handleAcceptChange(): Promise<void> {
    if (!keyChange) return;
    await acceptKeyChange(contact.accountId, keyChange.newSigningKey, keyChange.newDhKey);
    setKeyChange(null);
    onClose();
  }

  async function handleVerify(): Promise<void> {
    await setContactVerified(contact.accountId, true);
    onClose();
  }

  return (
    <Modal title={`Verify safety number with ${contact.nickname || contact.username}`} onClose={onClose}>
      {keyChange ? (
        <div className="space-y-3">
          <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-300">
            <strong>This contact's key has changed.</strong> They may have reinstalled, switched devices — or someone (including a compromised
            server) could be attempting to intercept your conversation. Only continue if you've confirmed this out-of-band.
          </div>
          <button onClick={handleAcceptChange} className={primaryButtonClass}>
            Accept the new key and re-verify
          </button>
          <button onClick={() => setKeyChange(null)} className={secondaryButtonClass}>
            Cancel
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Compare this number with {contact.nickname || contact.username} over a trusted channel (in person, a phone call). If it matches on
            both devices, your conversation cannot be intercepted by anyone — including the server.
          </p>
          {qrDataUrl && <img src={qrDataUrl} alt="Safety number QR code" className="mx-auto rounded-lg" />}
          <p className="break-all rounded-lg bg-slate-100 p-3 text-center font-mono text-sm tracking-wider text-slate-800 dark:bg-slate-800 dark:text-slate-100">
            {safetyNumber}
          </p>
          {contact.verified && (
            <p className="text-center text-sm text-emerald-600 dark:text-emerald-400">✓ You've verified this safety number</p>
          )}
          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
          <div className="flex gap-2">
            <button onClick={handleVerify} className={primaryButtonClass}>
              Mark as verified
            </button>
            <button onClick={handleCheck} disabled={checking} className={secondaryButtonClass}>
              {checking ? "Checking…" : "Check for key change"}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
