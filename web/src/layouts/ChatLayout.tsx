import type { ReactElement } from "react";
import { Outlet } from "react-router-dom";
import NavRail from "../components/NavRail.js";
import ConversationListPane from "../components/ConversationListPane.js";

export default function ChatLayout(): ReactElement {
  return (
    <div className="flex h-screen">
      <NavRail />
      <ConversationListPane />
      <div className="flex-1 overflow-hidden">
        <Outlet />
      </div>
    </div>
  );
}
