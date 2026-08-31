# Threat model

Status: **binding**. If an implementation shortcut would violate a rule here,
the shortcut is a bug.

## Assets

- Long-term Ed25519 identity private keys
- Trust-store membership (who may manage whom)
- ManagementIntents (configuration, app, service, command, desktop)
- Inventory and audit history
- Remote-desktop pixel/input streams (later) and authorization mode (now)
- Operator-supplied admin/root passwords used only as ephemeral elevation proofs
- Local Badger data at rest
- Enrollment tokens and issuer-signed installer policy
- Publisher-signed self-update artifacts

## Adversaries

- Network attacker on LAN/WAN/DHT/relay (read, inject, replay, MITM)
- Unpaired node that can reach a listen port
- Compromised FSE node that shares a host or a discovery channel
- Local unprivileged user on a managed endpoint
- Malicious or buggy replica attempting to merge another product's store files
- Operator mistake (sending a password in a ticket, log, or backup comment)
- Malicious mesh peer offering a self-signed "update"
- Stolen installer tree reused after revocation or expiry

## Trust boundaries

1. **Process**: console/agent memory vs disk vs network vs logs.
2. **Identity**: cryptographic node ID, not IP, hostname, or DHT name.
3. **Pairing**: explicit trust insert. Discovery never crosses this boundary.
4. **Session**: AEAD after signed hello; inner payloads are authenticated.
5. **Authorization**: even a trusted peer may only submit intents the target
   policy accepts (command execution is denied in this milestone).
6. **Privilege**: remote unattended-desktop enablement requires a target
   admin/root proof or physical/local admin access.
7. **Product**: RMM store vs FSE store. Separate directories, prefixes, and
   backup streams.

## Rules that must hold

### Discovery grants nothing

Local discovery, DHT, peer exchange, configured addresses, relays, and tunnels
may produce candidates. Candidates are untrusted. Completing a connection,
accepting a relay/tunnel offer, or applying an intent requires verification that
the peer holds the private key for a public key already in the local trust
store.

### No unauthenticated public desktop listener

Remote desktop MUST NOT bind a VNC/RDP/RFB/websocket viewer port that anyone on
the network can attach to. Viewer access uses the same authenticated mesh
session as intents. Install-time mode only chooses whether a **trusted** viewer
also needs an interactive user consent each session.

### Elevation passwords are ephemeral

When a remote operator changes `authorization-required` to `unattended`:

- The target may accept a one-shot admin/root password (or equivalent OS proof).
- The verifier uses the secret in memory and then **zeroes** it.
- The secret MUST NOT be written to Badger, JSON exports, interop records,
  receipts, audit events, stdout, or structured logs.
- The secret is ephemeral: never persist, log, or replicate it.
- If the OS has no usable admin password (passwordless sudo with no secret,
  blank Administrator, etc.), the change is refused unless the caller has
  **direct local access** (same machine, already-elevated agent install path).

### Store isolation

- Prefixes start with `rmm/v1/` or `interop/mgmt/v1/`.
- Never read or write `fse/v1/` keys.
- Never open another process's Badger directory.
- Interop records are versioned, signed by the origin identity, and encrypted
  to the recipient identity. They carry management metadata only (capability
  ads, presence, optional intent *references*), never file blocks or FSE
  manifests.

### Idempotency and replay

Intents carry `ID` and `IdempotencyKey`. Replays of a succeeded intent return
the original receipt. AEAD session counters reject replayed ciphertext.
Handshake nonces are single-use per session.

### Command execution

`command.run` is modeled but must fail closed until a later authz policy lands.
A trusted-but-malicious console must not get a root shell from this milestone.

### Logging

Logs and receipts may include node IDs, intent IDs, kinds, status, and redacted
error strings. They must not include passwords, private keys, session keys,
raw enrollment tokens, or raw elevation proofs. `internal/security` is the
redaction gate.

### Enrollment and installers

Identity-signed enrollment is not a substitute that can be skipped in favor of
OS code signing alone. Installers must not contain reusable private keys,
unrestricted credentials, or unrestricted network access. Tokens are one-time
or scoped; raw tokens are not stored in Badger.

### Self-update

A GitHub or mesh-cached artifact is untrusted until the recipient verifies the
**publisher** signature, hash, version policy, OS/arch (on apply), and expiry.
Paired peers cannot substitute their own signing key.

## Non-goals for this milestone (still constrained)

- Full remote-desktop capture/encode/input
- libp2p/DHT production routing
- Package-manager backends
- Multi-hop onion relays
- At-rest encryption of the whole Badger directory (follow-up; private keys
  still must not leak through interop/export filters)

## Abuse cases the tests must cover

1. Untrusted TCP client is disconnected before any intent is accepted.
2. Tampered hello signature fails.
3. Duplicate intent does not double-apply.
4. Desktop mode upgrade without proof fails; with proof succeeds; secret absent
   from store export.
5. Interop encoder rejects FSE file/block payload types.
6. Enrollment with `0.0.0.0/0` or a second consume is refused; raw token absent
   from the store.
7. Mesh peer cannot introduce an update signed by a non-publisher key.
8. Console refuses to apply endpoint-management intents.
