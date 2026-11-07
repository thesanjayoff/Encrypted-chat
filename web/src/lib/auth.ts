import * as opaque from "@serenity-kit/opaque";
import { toBase64 } from "@e2e-chat/crypto";
import { randomUUID } from "./uuid.js";
import { api, setSessionToken } from "./api.js";
import { vault } from "./vault.js";
import { createLocalIdentity, hasLocalIdentity, loadLocalIdentity } from "./identity.js";
import { db } from "./db.js";

export interface Session {
  accountId: string;
  username: string;
  deviceId: string;
  sessionToken: string;
}

const SESSION_STORAGE_KEY = "e2e-chat-session"; // token only; never any key material

export async function register(username: string, password: string, appLockPasscode: string | null): Promise<Session> {
  await opaque.ready;
  if (await hasLocalIdentity()) {
    throw new Error("This browser profile already has an identity. Use a different profile to register a second account, or link a device.");
  }

  await vault.initialize(appLockPasscode);

  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password });
  const startRes = await api.post<{ registrationResponse: string }>("/api/auth/register/start", { username, registrationRequest });

  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse: startRes.registrationResponse,
    password,
  });

  const deviceId = randomUUID();
  const { identity, signedPreKey, oneTimePreKeys } = await createLocalIdentity("pending", username, deviceId);

  const finishRes = await api.post<{ accountId: string; deviceId: string; sessionToken: string }>("/api/auth/register/finish", {
    username,
    registrationRecord,
    identitySigningPublicKey: toBase64(identity.signing.publicKey),
    identityDhKey: toBase64(identity.dh.publicKey),
    device: {
      label: navigator.userAgent.slice(0, 60),
      signedPreKeyId: signedPreKey.keyId,
      signedPreKeyPublic: toBase64(signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64(signedPreKey.signature),
      oneTimePreKeys: oneTimePreKeys.map((k) => ({ keyId: k.keyId, publicKey: toBase64(k.keyPair.publicKey) })),
    },
  });

  // We used a placeholder "pending" accountId locally (the server assigns
  // the real one); fix it up now that we know it.
  await db.identity.update("self", { accountId: finishRes.accountId });

  const session: Session = { accountId: finishRes.accountId, username, deviceId: finishRes.deviceId, sessionToken: finishRes.sessionToken };
  setSessionToken(session.sessionToken);
  persistSession(session);
  return session;
}

/** Logging back in on a device that already has local identity data (the
 * usual case: same browser profile as registration, or a previously linked
 * device). OPAQUE re-proves the password; it does not and cannot re-create
 * lost local key material — see README for why this app has no "forgot
 * password" account recovery. */
export async function login(password: string, appLockPasscode: string | null): Promise<Session> {
  await opaque.ready;
  const unlocked = appLockPasscode ? await vault.unlockWithPasscode(appLockPasscode) : await vault.tryAutoUnlock();
  if (!unlocked) throw new Error("Could not unlock local data — wrong passcode?");

  const local = await loadLocalIdentity();
  if (!local) throw new Error("No local identity found on this device. Register, or link this device from one that already has an account.");

  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
  const startRes = await api.post<{ loginId: string; loginResponse: string }>("/api/auth/login/start", {
    username: local.username,
    startLoginRequest,
  });

  const loginResult = opaque.client.finishLogin({ clientLoginState, loginResponse: startRes.loginResponse, password });
  if (!loginResult) throw new Error("Incorrect password");

  const finishRes = await api.post<{ accountId: string; deviceId: string; sessionToken: string }>("/api/auth/login/finish", {
    loginId: startRes.loginId,
    finishLoginRequest: loginResult.finishLoginRequest,
    deviceId: local.deviceId,
  });

  const session: Session = { accountId: finishRes.accountId, username: local.username, deviceId: finishRes.deviceId, sessionToken: finishRes.sessionToken };
  setSessionToken(session.sessionToken);
  persistSession(session);
  return session;
}

/** For the common case: a valid session token is already in sessionStorage
 * (same tab, just reloaded) and only the local vault needs unlocking —
 * no OPAQUE round-trip required. */
export async function unlockOnly(passcode: string | null): Promise<Session> {
  const persisted = loadPersistedSession();
  if (!persisted) throw new Error("No session to resume — log in instead");
  const unlocked = passcode ? await vault.unlockWithPasscode(passcode) : await vault.tryAutoUnlock();
  if (!unlocked) throw new Error("Could not unlock local data — wrong passcode?");
  setSessionToken(persisted.sessionToken);
  return persisted;
}

export function persistSession(session: Session): void {
  sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
}

export function loadPersistedSession(): Session | null {
  const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function clearPersistedSession(): void {
  sessionStorage.removeItem(SESSION_STORAGE_KEY);
  setSessionToken(null);
}
