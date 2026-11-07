import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { URL } from "node:url";
import { PORT } from "./env.js";
import "./db.js"; // ensures schema is created before anything else runs
import { createApp } from "./app.js";
import { handleGatewaySocket } from "./ws/gateway.js";
import { handleLinkSocket } from "./ws/linkRelay.js";
import { startRetentionSweeper } from "./retention.js";

const app = createApp();
const httpServer = createServer(app);
const wss = new WebSocketServer({ noServer: true });

httpServer.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/ws") {
    wss.handleUpgrade(req, socket, head, (ws) => {
      handleGatewaySocket(ws, url.searchParams.get("token"));
    });
  } else if (url.pathname === "/ws/link") {
    const token = url.searchParams.get("token");
    if (!token) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      handleLinkSocket(ws, token);
    });
  } else {
    socket.destroy();
  }
});

startRetentionSweeper();

httpServer.listen(PORT, () => {
  console.log(`[server] listening on http://localhost:${PORT}`);
});
