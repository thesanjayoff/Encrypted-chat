import type { ReactElement } from "react";
import { NavLink } from "react-router-dom";
import { useSession } from "../context/SessionContext.js";

function NavButton({ to, label, children }: { to: string; label: string; children: React.ReactNode }): ReactElement {
  return (
    <NavLink
      to={to}
      title={label}
      className={({ isActive }) =>
        `flex h-10 w-10 items-center justify-center rounded-lg text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100 ${
          isActive ? "bg-brand-50 text-brand-600 dark:bg-brand-900/30 dark:text-brand-400" : ""
        }`
      }
    >
      {children}
    </NavLink>
  );
}

export default function NavRail(): ReactElement {
  const { identity, logout } = useSession();

  return (
    <div className="flex h-full w-16 flex-col items-center justify-between border-r border-slate-200 bg-white py-4 dark:border-slate-800 dark:bg-slate-900">
      <div className="flex flex-col items-center gap-2">
        <div className="mb-2 flex h-9 w-9 items-center justify-center rounded-lg bg-brand-600 text-sm font-semibold text-white" title={identity?.username}>
          {identity?.username.slice(0, 2).toUpperCase()}
        </div>
        <NavButton to="/" label="Chats">
          <ChatIcon />
        </NavButton>
        <NavButton to="/devices" label="Devices">
          <DeviceIcon />
        </NavButton>
        <NavButton to="/settings" label="Settings">
          <GearIcon />
        </NavButton>
      </div>
      <button
        onClick={logout}
        title="Log out"
        className="flex h-10 w-10 items-center justify-center rounded-lg text-slate-400 transition hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/40"
      >
        <LogoutIcon />
      </button>
    </div>
  );
}

function ChatIcon(): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
      <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
    </svg>
  );
}
function DeviceIcon(): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
      <rect x="4" y="2" width="10" height="20" rx="2" />
      <path d="M17 7h3M17 12h3M17 17h3" />
    </svg>
  );
}
function GearIcon(): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}
function LogoutIcon(): ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <path d="M16 17l5-5-5-5" />
      <path d="M21 12H9" />
    </svg>
  );
}
