import type { ReactElement } from "react";
import type { ReactNode } from "react";

export default function AuthCard({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }): ReactElement {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 px-4 dark:bg-slate-950">
      <div className="w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 text-white">
            <LockIcon />
          </div>
          <span className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">E2E Chat</span>
        </div>
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{subtitle}</p>}
        <div className="mt-6">{children}</div>
      </div>
    </div>
  );
}

export function LockIcon({ className = "h-4 w-4" }: { className?: string }): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={className}>
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

export function FieldError({ message }: { message: string | null }): ReactElement | null {
  if (!message) return null;
  return <p className="mt-2 text-sm text-red-600 dark:text-red-400">{message}</p>;
}

export const inputClass =
  "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none ring-brand-500/30 focus:border-brand-500 focus:ring-2 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100";

export const primaryButtonClass =
  "w-full rounded-lg bg-brand-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-brand-700 disabled:cursor-not-allowed disabled:opacity-50";

export const secondaryButtonClass =
  "w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-50 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800";
