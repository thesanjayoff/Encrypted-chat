import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import * as opaque from "@serenity-kit/opaque";

// Must run before anything imports src/env.ts, so these win over .env /
// defaults (dotenv does not overwrite already-set process.env vars).
process.env.DB_PATH = ":memory:";
process.env.ATTACHMENTS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "e2e-chat-test-attachments-"));
process.env.CORS_ORIGIN = "http://localhost:5173";
// High by default so ordinary functional tests aren't flaky against a limit
// sized for a real abusive client; rateLimit.test.ts overrides these back
// down per-test to actually exercise 429 behavior.
process.env.RATE_LIMIT_AUTH = "100000";
process.env.RATE_LIMIT_PREKEY_FETCH = "100000";
process.env.RATE_LIMIT_API = "100000";

await opaque.ready;
process.env.OPAQUE_SERVER_SETUP = opaque.server.createSetup();
