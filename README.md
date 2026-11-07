# e2e-chat

A personal end-to-end encrypted chat app, built from scratch as a learning
and portfolio project.

> **This is not audited software.** It was built to learn and demonstrate
> the Signal-style protocols (X3DH, Double Ratchet, Sender Keys, OPAQUE) end
> to end, not reviewed by a cryptographer, and not something you should trust
> with anyone's safety. See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for an
> honest account of what it does and doesn't defend against, and what the
> server operator can still see.

## What's here

- **1:1 chat** with forward secrecy and post-compromise security (Double
  Ratchet over an X3DH-negotiated session).
- **Group chat** via Sender Keys (Signal's approach), rotated and
  redistributed to the remaining members on every membership change.
- **Safety numbers** to verify a contact's identity key out-of-band, with a
  warning when a contact's key changes.
- **Multi-device support**: link a new device by scanning/relaying an
  ephemeral-ECDH handshake the server can't read; the new device inherits
  the account's existing identity key (and therefore its safety number).
- **Encrypted attachments**, message padding (to bucketed sizes), disappearing
  messages, and "delete for everyone" (both client-enforced; see the threat
  model's limitations section).
- **OPAQUE password authentication** — the server never sees your password
  or anything brute-forceable from a database dump.
- A deliberately "boring" server: it stores ciphertext, public keys, and the
  minimum routing metadata needed to deliver a message, nothing more.

Web client only for now; the crypto and protocol logic live in a separate
package (`packages/crypto`) specifically so a mobile client can reuse them
later.

## Project layout

```
packages/crypto/   X3DH, Double Ratchet, Sender Keys, safety numbers — the
                   only place cryptographic primitives are touched directly.
server/            Express + ws "boring server": OPAQUE auth, key bundles,
                   message relay/queueing, groups, devices, attachments.
web/                React 19 + Vite + TypeScript client. All private key
                   material and session state lives client-side, in
                   IndexedDB, sealed by a local vault key (see
                   web/src/lib/vault.ts).
```

## Running it locally

Requires Node.js 20+.

```bash
npm install
```

### 1. Start the server

```bash
cp server/.env.example server/.env   # edit if you want non-default ports/paths
npm run dev:server
```

This starts the Express + WebSocket server on `http://localhost:4000` (set
`PORT` in `server/.env` to change it), backed by a local SQLite file at
`server/data/server.sqlite` by default. On first run it generates an OPAQUE
server setup key and writes it back into `server/.env` — don't rotate that
value afterward, or every registered account will be locked out.

### 2. Start the web client

```bash
npm run dev:web
```

Opens the Vite dev server at `http://localhost:5173`. It talks to the server
at `http://localhost:4000` by default; set `VITE_API_URL` in `web/.env` if
you changed the server's port.

### 3. Try it

Open the web app in two separate browser profiles (or a normal + incognito
window — this app uses IndexedDB for all local state, which is per-origin and
shared across tabs of the *same* profile, so two accounts in one profile will
collide). Register two accounts, add each other as contacts by username,
compare safety numbers, and start chatting.

## Running the tests

```bash
npm test
```

Runs every workspace's test suite (`vitest`), including:

- `packages/crypto/test/` — known-answer and property tests for X3DH, the
  Double Ratchet (including forward-secrecy / post-compromise-security
  tests and skipped-message handling), Sender Keys, and safety numbers.
- `server/test/malicious-server.test.ts` — asserts a fully compromised
  server (arbitrary read/write access to its own database) still cannot
  recover plaintext, private keys, or usable attachment keys.
- `server/test/` — auth, messaging, rate limiting, and groups routes.

## No subscriptions, no billing

Everything runs locally against your own server instance. There is no
hosted backend, no account tier, and no paid feature.

## Known limitations

See the "Known limitations" section of
[`THREAT_MODEL.md`](./THREAT_MODEL.md) — kept up to date there rather than
duplicated here.
