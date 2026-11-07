import type { ReactElement } from "react";
import { useState } from "react";
import type { MessageRow } from "../lib/db.js";
import { readPlaintext, type PlaintextPayload } from "../lib/messaging.js";
import { downloadAndDecryptAttachment } from "../lib/attachments.js";

function timeLabel(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

export default function MessageBubble({
  row,
  senderLabel,
  onDeleteForEveryone,
}: {
  row: MessageRow;
  senderLabel?: string;
  onDeleteForEveryone?: (messageId: string) => void;
}): ReactElement {
  const isOut = row.direction === "out";
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  if (row.deletedForEveryone) {
    return (
      <div className={`flex ${isOut ? "justify-end" : "justify-start"}`}>
        <div className="max-w-md rounded-2xl bg-slate-100 px-4 py-2 text-sm italic text-slate-400 dark:bg-slate-800 dark:text-slate-500">
          This message was deleted
        </div>
      </div>
    );
  }

  let payload: PlaintextPayload;
  try {
    payload = readPlaintext(row);
  } catch {
    return (
      <div className={`flex ${isOut ? "justify-end" : "justify-start"}`}>
        <div className="max-w-md rounded-2xl bg-red-50 px-4 py-2 text-sm text-red-500 dark:bg-red-950/40">Could not decrypt this message</div>
      </div>
    );
  }

  async function handleDownload(): Promise<void> {
    if (payload?.kind !== "attachment" || !payload.attachment) return;
    setDownloading(true);
    setDownloadError(null);
    try {
      const blob = await downloadAndDecryptAttachment(payload.attachment);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = payload.attachment.filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : "Download failed");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className={`group flex ${isOut ? "justify-end" : "justify-start"}`}>
      <div className="max-w-md">
        {senderLabel && !isOut && <p className="mb-0.5 px-1 text-xs font-medium text-slate-400">{senderLabel}</p>}
        <div
          className={`rounded-2xl px-4 py-2 text-sm ${
            isOut ? "bg-brand-600 text-white" : "bg-white text-slate-900 shadow-sm dark:bg-slate-800 dark:text-slate-100"
          }`}
        >
          {payload.kind === "text" && <p className="whitespace-pre-wrap break-words">{payload.text}</p>}
          {payload.kind === "system" && <p className="italic opacity-80">{payload.text}</p>}
          {payload.kind === "attachment" && payload.attachment && (
            <div>
              <p className="flex items-center gap-2">
                <PaperclipIcon />
                <span className="truncate">{payload.attachment.filename}</span>
              </p>
              <button onClick={handleDownload} disabled={downloading} className="mt-1 text-xs underline opacity-90 hover:opacity-100">
                {downloading ? "Downloading…" : "Download"}
              </button>
              {downloadError && <p className="mt-1 text-xs text-red-300">{downloadError}</p>}
            </div>
          )}
        </div>
        <p className={`mt-0.5 flex items-center gap-2 px-1 text-xs text-slate-400 ${isOut ? "justify-end" : ""}`}>
          {timeLabel(row.createdAt)}
          {isOut && onDeleteForEveryone && (
            <button
              onClick={() => onDeleteForEveryone(row.id)}
              className="opacity-0 transition hover:text-red-500 group-hover:opacity-100"
              title="Delete for everyone"
            >
              Delete
            </button>
          )}
        </p>
      </div>
    </div>
  );
}

function PaperclipIcon(): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4 shrink-0">
      <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
    </svg>
  );
}
