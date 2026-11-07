# Threat Model

This is a personal learning / portfolio project. It is **not audited** and must
not be relied on to protect anyone whose safety depends on it. This document is
written first and updated as the system changes, so it stays honest about what
is and is not actually true of the running code.

## Goals

Give two or more people a chat where the server operator — or anyone who
compromises the server — cannot read message content, past or future, even if
they also compromise the network link.

## In scope (the system defends against these)

- **A fully compromised server operator or database breach.** The server
  stores only ciphertext, public keys, and routing metadata. Dumping the
  entire database and logs must not reveal plaintext, private keys, or usable
  attachment-decryption keys. Verified by an automated "malicious server"
  test (`server/test/malicious-server.test.ts`).
- **A passive or active network eavesdropper (MITM on the wire).** TLS
  protects the transport; independently, message confidentiality does not
  depend on TLS — ciphertext is already end-to-end encrypted before it
  reaches the socket.
- **A malicious or compromised server trying to substitute keys** (the
  "unknown key share" / key-substitution attack). Mitigated by safety-number
  verification (a hash of both parties' identity keys) that users can compare
  out-of-band; the UI surfaces a warning whenever a contact's long-term
  identity key changes.
- **Replay of old ciphertext.** The Double Ratchet's per-message keys and the
  server's one-time delivery/ack model mean a replayed envelope either fails
  to decrypt (key already advanced/deleted) or is a harmless duplicate the
  client recognizes and drops.
- **Loss of a single message key / session key at one point in time**
  (forward secrecy) and **recovery after such a compromise once new ratchet
  messages are exchanged** (post-compromise security) — both are properties
  of the Double Ratchet and are covered by dedicated tests.
- **A removed group member reading messages sent after their removal** — group
  sessions rotate the Sender Key when membership changes.
- **Resource-exhaustion of the prekey pool** — rate limiting and prekey
  replenishment bounds are enforced server-side.

## Out of scope (this system does **not** defend against these)

- **A compromised or stolen *unlocked* device.** If the device itself is
  compromised (malware, physical access while unlocked, a malicious client
  build), plaintext and in-memory keys are exposed. App Lock / local DB
  encryption raises the bar for a *locked* device but is not a defense
  against a compromised OS or an attacker with code execution on the device.
- **Metadata the server must see to do its job**: account identifiers, the
  fact that two accounts correspond (unless sealed-sender is enabled, in
  which case the server still sees the *recipient* and approximate timing),
  message sizes (padded, but padding has limits), approximate send/receive
  timestamps, and IP address (minimized retention, not eliminated).
- **Traffic analysis by a global passive adversary** (timing/size
  correlation across many users). Padding and sealed-sender raise cost, they
  do not eliminate this class of attack.
- **Endpoint compromise of the *other* party.** E2EE guarantees that only the
  two endpoints can read a message — it says nothing about what the other
  endpoint does with it afterward (screenshots, forwarding, a compromised
  recipient device).
- **Denial of service beyond basic rate limiting.** This is a hobby project,
  not a hardened production service; it does not defend against a
  well-resourced DoS attacker.
- **Side-channel attacks** (timing of non-constant-time comparisons we failed
  to avoid, cache timing, power analysis, etc.) beyond using constant-time
  primitives from libsodium for secret comparisons.
- **Supply-chain compromise of a dependency.** We depend on `libsodium-wrappers`
  and a small set of maintained npm packages; we do not reproduce or audit
  their build pipelines.
- **Quantum adversaries.** X3DH here uses classical X25519, not PQXDH — no
  post-quantum protection is claimed.

## Design choices made to minimize what the server can see

- Public keys and ciphertext only — no plaintext, no plaintext contact
  lists, no message bodies in logs.
- Short default retention: queued ciphertext is deleted immediately on
  successful delivery, and anything undelivered expires automatically.
- Optional sealed-sender mode so the delivering server does not need the
  sender's identity to route a message to the recipient (see `server/src/sealedSender.ts`).
- Message padding to bucketed sizes before encryption, to blunt (not
  eliminate) length-based content guessing.

## Cryptographic building blocks (all from vetted libraries, never hand-rolled)

- Primitives: libsodium (`libsodium-wrappers`) — X25519, Ed25519, XChaCha20-Poly1305
  AEAD, BLAKE2b, Argon2id, a CSPRNG (`randombytes_buf`).
- Key agreement: X3DH, built from the primitives above following the published
  Signal spec (https://signal.org/docs/specifications/x3dh/).
- Message encryption: the Double Ratchet, built from the primitives above
  following the published Signal spec
  (https://signal.org/docs/specifications/doubleratchet/).
- Group messaging: Sender Keys (Signal's approach — a per-sender symmetric
  ratchet distributed 1:1 to each member over an already-established Double
  Ratchet session), not a hand-rolled scheme.
- Password authentication: OPAQUE (a real PAKE — the server never sees the
  password or a function of it that could be brute-forced offline from a
  database dump), via an audited OPAQUE implementation. See `server/README.md`
  for the exact tradeoff if a fallback (salted Argon2id) is used instead.

Where protocol logic (X3DH, Double Ratchet, Sender Keys) is implemented in
this repo rather than imported wholesale from `libsignal`, it is implemented
strictly from the published specification on top of libsodium primitives, and
tested against known-answer / interoperability-style tests in
`packages/crypto/test/`.

## Known limitations of this implementation (keep this section current)

- Group messaging uses Sender Keys, not MLS — simpler, but a removed member
  who retained the last-known chain key before removal could, in a naive
  implementation, be lied-to by a malicious admin about removal. We rotate
  and redistribute the Sender Key to all *remaining* members on every
  membership change precisely to avoid this; see `packages/protocol/src/senderKeys.ts`.
- There is no X3DH→PQXDH upgrade path yet.
- Sealed sender is best-effort: the server still learns the recipient and
  coarse timing.
