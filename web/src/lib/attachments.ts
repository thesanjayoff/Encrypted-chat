import { aeadEncrypt, aeadDecrypt, randomBytes, toBase64, fromBase64, AEAD_KEY_BYTES, AEAD_NONCE_BYTES } from "@e2e-chat/crypto";
import { api } from "./api.js";

export const MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024;
const ALLOWED_MIME_PREFIXES = ["image/", "video/", "audio/", "application/pdf", "text/plain"];

export interface EncryptedAttachmentRef {
  attachmentId: string;
  filename: string;
  mimeType: string;
  size: number;
  decryptionKey: string; // base64 — travels only inside the E2E-encrypted message
}

function assertAllowed(file: File): void {
  if (file.size > MAX_ATTACHMENT_BYTES) throw new Error(`File too large (max ${Math.floor(MAX_ATTACHMENT_BYTES / 1024 / 1024)} MB)`);
  if (!ALLOWED_MIME_PREFIXES.some((p) => file.type.startsWith(p))) {
    throw new Error(`File type "${file.type || "unknown"}" isn't allowed`);
  }
}

/** Encrypts `file` with a fresh random key (never sent to the server) and
 * uploads only the ciphertext. The returned ref — including the key —
 * must travel inside a normal end-to-end-encrypted message; the server
 * never sees the key or the plaintext. */
export async function encryptAndUploadAttachment(file: File): Promise<EncryptedAttachmentRef> {
  assertAllowed(file);
  const key = randomBytes(AEAD_KEY_BYTES);
  const nonce = randomBytes(AEAD_NONCE_BYTES);
  const plaintext = new Uint8Array(await file.arrayBuffer());
  const ciphertext = aeadEncrypt(key, nonce, plaintext);

  // nonce || ciphertext, so the key alone (plus this blob) is everything
  // needed to decrypt — matches how vault.ts packs its own blobs.
  const body = new Uint8Array(nonce.length + ciphertext.length);
  body.set(nonce, 0);
  body.set(ciphertext, nonce.length);

  const { id } = await api.postRaw<{ id: string }>("/api/attachments", body);
  return { attachmentId: id, filename: file.name, mimeType: file.type || "application/octet-stream", size: file.size, decryptionKey: toBase64(key) };
}

export async function downloadAndDecryptAttachment(ref: EncryptedAttachmentRef): Promise<Blob> {
  const buffer = await api.get<ArrayBuffer>(`/api/attachments/${ref.attachmentId}`);
  const body = new Uint8Array(buffer);
  const nonce = body.slice(0, AEAD_NONCE_BYTES);
  const ciphertext = body.slice(AEAD_NONCE_BYTES);
  const plaintext = aeadDecrypt(fromBase64(ref.decryptionKey), nonce, ciphertext);
  return new Blob([plaintext as BlobPart], { type: ref.mimeType });
}
