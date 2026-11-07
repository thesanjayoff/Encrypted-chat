import { API_BASE } from "./config.js";

let sessionToken: string | null = null;

export function setSessionToken(token: string | null): void {
  sessionToken = token;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown, raw?: Uint8Array): Promise<T> {
  const headers: Record<string, string> = {};
  if (sessionToken) headers.authorization = `Bearer ${sessionToken}`;
  let requestBody: BodyInit | undefined;
  if (raw) {
    headers["content-type"] = "application/octet-stream";
    requestBody = raw as BodyInit;
  } else if (body !== undefined) {
    headers["content-type"] = "application/json";
    requestBody = JSON.stringify(body);
  }

  const res = await fetch(`${API_BASE}${path}`, { method, headers, body: requestBody });
  const isJson = res.headers.get("content-type")?.includes("application/json");
  if (!res.ok) {
    const errBody = isJson ? await res.json().catch(() => ({})) : {};
    throw new ApiError(res.status, errBody.error ?? `request failed with ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  if (!isJson) return (await res.arrayBuffer()) as unknown as T;
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  postRaw: <T>(path: string, body: Uint8Array) => request<T>("POST", path, undefined, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};
