import type { ReactElement } from "react";
import { LockIcon } from "../components/AuthCard.js";

export default function ConversationsPage(): ReactElement {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 text-slate-400">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800">
        <LockIcon className="h-6 w-6" />
      </div>
      <p className="text-sm">Select a conversation, or add a contact to start one.</p>
    </div>
  );
}
