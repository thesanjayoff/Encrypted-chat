import fs from "node:fs";
import path from "node:path";
import dotenv from "dotenv";
import * as opaque from "@serenity-kit/opaque";

const ENV_PATH = path.resolve(process.cwd(), ".env");
dotenv.config({ path: ENV_PATH });

export const PORT = Number(process.env.PORT ?? 4000);
export const DB_PATH =
  process.env.DB_PATH === ":memory:" ? ":memory:" : path.resolve(process.cwd(), process.env.DB_PATH ?? "./data/server.sqlite");
export const ATTACHMENTS_DIR = path.resolve(process.cwd(), process.env.ATTACHMENTS_DIR ?? "./attachments");
export const CORS_ORIGIN = process.env.CORS_ORIGIN ?? "http://localhost:5173";

/** The OPAQUE server setup is a long-term server secret: it must stay
 * identical across restarts (changing it invalidates every account's
 * ability to log in) but must never be derived from anything guessable.
 * If it's missing from .env (first run), generate one and persist it —
 * same spirit as "keep secrets in environment variables," minus a manual
 * setup step for a learning project that should just run. */
export async function getOpaqueServerSetup(): Promise<string> {
  await opaque.ready;
  let setup = process.env.OPAQUE_SERVER_SETUP;
  if (setup) return setup;

  setup = opaque.server.createSetup();
  appendOrCreateEnvVar("OPAQUE_SERVER_SETUP", setup);
  process.env.OPAQUE_SERVER_SETUP = setup;
  console.warn(
    "[env] Generated a new OPAQUE_SERVER_SETUP and saved it to .env — do not commit this file, and do not change this value once real accounts exist.",
  );
  return setup;
}

function appendOrCreateEnvVar(key: string, value: string) {
  const line = `${key}=${value}\n`;
  if (!fs.existsSync(ENV_PATH)) {
    fs.writeFileSync(ENV_PATH, line, { mode: 0o600 });
    return;
  }
  const contents = fs.readFileSync(ENV_PATH, "utf8");
  if (new RegExp(`^${key}=`, "m").test(contents)) {
    fs.writeFileSync(ENV_PATH, contents.replace(new RegExp(`^${key}=.*$`, "m"), line.trimEnd()));
  } else {
    fs.appendFileSync(ENV_PATH, (contents.endsWith("\n") ? "" : "\n") + line);
  }
}
