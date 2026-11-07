import type { ReactElement } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useSession } from "./context/SessionContext.js";
import { useTheme } from "./hooks/useTheme.js";
import WelcomePage from "./pages/WelcomePage.js";
import RegisterPage from "./pages/RegisterPage.js";
import LinkDevicePage from "./pages/LinkDevicePage.js";
import LoginPage from "./pages/LoginPage.js";
import UnlockPage from "./pages/UnlockPage.js";
import ChatLayout from "./layouts/ChatLayout.js";
import ConversationsPage from "./pages/ConversationsPage.js";
import ConversationPage from "./pages/ConversationPage.js";
import SettingsPage from "./pages/SettingsPage.js";
import DevicesPage from "./pages/DevicesPage.js";

export default function App(): ReactElement {
  useTheme();
  const { status } = useSession();

  if (status === "loading") {
    return (
      <div className="flex h-screen items-center justify-center text-slate-400">
        <span className="animate-pulse text-sm">Loading…</span>
      </div>
    );
  }

  if (status === "no-identity") {
    return (
      <Routes>
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/link" element={<LinkDevicePage />} />
        <Route path="*" element={<WelcomePage />} />
      </Routes>
    );
  }

  if (status === "needs-unlock") {
    return <UnlockPage />;
  }

  if (status === "needs-login") {
    return <LoginPage />;
  }

  return (
    <Routes>
      <Route path="/" element={<ChatLayout />}>
        <Route index element={<ConversationsPage />} />
        <Route path="chat/:kind/:id" element={<ConversationPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="devices" element={<DevicesPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
