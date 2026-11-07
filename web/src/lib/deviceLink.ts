import {
  generateEphemeralKeyPair,
  x25519Dh,
  identityPublicKeysFrom,
  hkdf,
  aeadEncrypt,
  aeadDecrypt,
  randomBytes,
  concatBytes,
  utf8,
  fromUtf8,
  toBase64,
  fromBase64,
  AEAD_NONCE_BYTES,
  type IdentityKeyPair,
} from "@e2e-chat/crypto";
import { WS_BASE } from "./config.js";
import { api } from "./api.js";
import { db } from "./db.js";
import { createLocalIdentity } from "./identity.js";

/**
 * Device linking: the server only ever sees a one-time `linkToken` and
 * forwards opaque bytes between exactly two sockets (ws/linkRelay.ts) — it
 * cannot read what's exchanged. The two devices run their own ephemeral
 * X25519 handshake over that pipe, then AEAD-encrypt the account's
 * identity private key material before sending it, so a server that
 * relayed the bytes still learns nothing. Trust comes from the human
 * confirming the out-of-band QR/code match, exactly like safety numbers.
 */

const LINK_HANDSHAKE_INFO = utf8("E2EChat-DeviceLink-v1");

type LinkWireMessage = { type: "hello"; publicKey: string } | { type: "identity"; nonce: string; ciphertext: string } | { type: "done" };

interface TransferredIdentity {
  username: string;
  signingPrivateKey: string;
  dhPrivateKey: string;
}

function deriveLinkKey(sharedSecret: Uint8Array, hostPub: Uint8Array, joinerPub: Uint8Array): Uint8Array {
  return hkdf(sharedSecret, concatBytes(hostPub, joinerPub), LINK_HANDSHAKE_INFO, 32);
}

function openSocket(linkToken: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`${WS_BASE}/ws/link?token=${encodeURIComponent(linkToken)}`);
    socket.onopen = () => resolve(socket);
    socket.onerror = () => reject(new Error("could not open link channel"));
  });
}

function send(socket: WebSocket, msg: LinkWireMessage): void {
  socket.send(JSON.stringify(msg));
}

function onceMessage(socket: WebSocket): Promise<LinkWireMessage> {
  return new Promise((resolve, reject) => {
    socket.onmessage = (ev) => {
      try {
        resolve(JSON.parse(ev.data as string) as LinkWireMessage);
      } catch {
        reject(new Error("malformed link message"));
      }
    };
    socket.onclose = () => reject(new Error("link channel closed"));
  });
}

/** Run on the already-logged-in primary device, after it has displayed
 * `linkToken` (e.g. as a QR code). Resolves once the new device has
 * successfully registered itself. */
export async function hostDeviceLink(identity: IdentityKeyPair, username: string, linkToken: string): Promise<void> {
  const socket = await openSocket(linkToken);
  const ephemeral = generateEphemeralKeyPair();

  const helloPromise = onceMessage(socket);
  send(socket, { type: "hello", publicKey: toBase64(ephemeral.publicKey) });
  const hello = await helloPromise;
  if (hello.type !== "hello") throw new Error("unexpected message during link handshake");
  const peerPublic = fromBase64(hello.publicKey);

  const shared = x25519Dh(ephemeral.privateKey, peerPublic);
  const key = deriveLinkKey(shared, ephemeral.publicKey, peerPublic);

  const identityPayload = utf8(
    JSON.stringify({
      username,
      signingPrivateKey: toBase64(identity.signing.privateKey),
      dhPrivateKey: toBase64(identity.dh.privateKey),
    } satisfies TransferredIdentity),
  );
  const nonce = randomBytes(AEAD_NONCE_BYTES);
  const ciphertext = aeadEncrypt(key, nonce, identityPayload);

  const donePromise = onceMessage(socket);
  send(socket, { type: "identity", nonce: toBase64(nonce), ciphertext: toBase64(ciphertext) });
  const done = await donePromise;
  if (done.type !== "done") throw new Error("new device did not confirm linking");
  socket.close();
}

/** Run on the new device after scanning/entering `linkToken` from the
 * primary device's display. On success, this device has its own local
 * identity (inherited private keys, freshly generated device prekeys) and
 * an authenticated session, exactly as if it had just registered. */
export async function joinDeviceLink(linkToken: string, deviceId: string): Promise<{ accountId: string; deviceId: string; sessionToken: string }> {
  const socket = await openSocket(linkToken);
  const ephemeral = generateEphemeralKeyPair();

  const helloPromise = onceMessage(socket);
  send(socket, { type: "hello", publicKey: toBase64(ephemeral.publicKey) });
  const hello = await helloPromise;
  if (hello.type !== "hello") throw new Error("unexpected message during link handshake");
  const hostPublic = fromBase64(hello.publicKey);
  const shared = x25519Dh(ephemeral.privateKey, hostPublic);
  const key = deriveLinkKey(shared, hostPublic, ephemeral.publicKey);

  const identityMsg = await onceMessage(socket);
  if (identityMsg.type !== "identity") throw new Error("expected identity transfer");
  const plaintext = aeadDecrypt(key, fromBase64(identityMsg.nonce), fromBase64(identityMsg.ciphertext));
  const { username, signingPrivateKey, dhPrivateKey } = JSON.parse(fromUtf8(plaintext)) as TransferredIdentity;

  const signingPrivate = fromBase64(signingPrivateKey);
  const dhPrivate = fromBase64(dhPrivateKey);
  const { signingPublicKey, dhPublicKey } = identityPublicKeysFrom(signingPrivate, dhPrivate);
  const inheritedIdentity: IdentityKeyPair = {
    signing: { publicKey: signingPublicKey, privateKey: signingPrivate },
    dh: { publicKey: dhPublicKey, privateKey: dhPrivate },
  };

  const { signedPreKey, oneTimePreKeys } = await createLocalIdentity("pending", username, deviceId, inheritedIdentity);

  const finishRes = await api.post<{ accountId: string; deviceId: string; sessionToken: string }>("/api/devices/link/register", {
    linkToken,
    identitySigningPublicKey: toBase64(inheritedIdentity.signing.publicKey),
    identityDhKey: toBase64(inheritedIdentity.dh.publicKey),
    device: {
      label: navigator.userAgent.slice(0, 60),
      signedPreKeyId: signedPreKey.keyId,
      signedPreKeyPublic: toBase64(signedPreKey.keyPair.publicKey),
      signedPreKeySignature: toBase64(signedPreKey.signature),
      oneTimePreKeys: oneTimePreKeys.map((k) => ({ keyId: k.keyId, publicKey: toBase64(k.keyPair.publicKey) })),
    },
  });

  await db.identity.update("self", { accountId: finishRes.accountId });
  send(socket, { type: "done" });
  socket.close();
  return finishRes;
}
