# Architecture

Status: **binding foundation contract**. Implementation in this repository must
match these boundaries. Planned later work is labeled as such; it is not an
excuse to violate the security or data-isolation rules.

## Product

Decentralized-RMM is a native remote-management system:

- a separately deployable **console** (native GUI on Win32/X11/Aqua; not a TUI
  or mandatory web console) that is itself an authenticated mesh peer
- separately deployable **agents** on managed endpoints
- an **`rmm-pack`** deployment tool that emits identity-provisioned installers
- **local durable state** on every node
- **endpoint inventory**, desired-state jobs, app/service intents, receipts
- **remote desktop** (unattended or authorization-every-session)
- **secure self-update** with independently verified, mesh-cacheable artifacts

There is no required central server. Nodes form a trusted mesh. Relays and
tunnels are optional reachability aids after trust, never a substitute for it.

## Abandoned material

Do not resume:

- `archive/dotnet-windows-service/` (.NET Framework 4.6.1 Windows Service)
- rqlite, rhinodht, or IPFS as the data/discovery plane
- a Windows-only first product with "other OS later"

The live stack is Go, BadgerDB behind a store interface, Ed25519 identities,
X25519 + XChaCha20-Poly1305 sessions, and OS-native integrations.

## Process model

```
[ operator ]
    |
    v
[ rmm-console ] --local auth session--> [ rmm-agent on same host, if trusted ]
    |                                              |
    +---- else built-in authenticated mesh --------+
    |                                              |
    v                                              v
[ Badger rmm/v1/* ]                          [ Badger rmm/v1/* ]
    |                                              |
    +---- optional interop/mgmt/v1 after trust ----+
                     |
                     v
              [ File-Sync-Engine ]
              (separate process, separate DB)

[ rmm-pack ] --identity-signed enrollment--> [ platform-native installer tree ]
```

`rmm-console`, `rmm-agent`, and `rmm-pack` are separately deployable native
programs. Dual-role is withdrawn. The console has **no** endpoint-management
agent function. If a compatible trusted platform agent runs on the same
computer, the native GUI prefers a local authenticated connection and reuses
that agent's mesh presence; otherwise it starts its own built-in authenticated
mesh (identity, DHT/routing candidates, discovery, relay/tunnel planning,
artifact cache). A browser is not the control plane. There is no TUI product.

Installer enrollment, policy visibility, and self-update contracts are in
`docs/ENROLLMENT.md`, `docs/DEPLOYMENT.md`, `docs/CONSOLE.md`, and
`docs/SELF_UPDATE.md`.

## Trust plane

1. Each node has a long-term **Ed25519** identity. Node ID is
   `rmm1:` plus the URL-safe Base64 SHA-256 fingerprint of the public key.
2. **Pairing** writes the peer's public key into the local trust store.
3. **Discovery** (local, DHT, peer exchange, configured peers, relays, tunnels)
   only yields candidates. Discovery grants no authority.
4. A session is opened only after the peer proves the trusted identity with a
   signed hello that includes the ephemeral X25519 session key.
5. Relay or tunnel **offers** are likewise rejected until that proof succeeds.

Reuse from File-Sync-Engine is conceptual only: identity packages, trust-before-
traffic, management-path preference for direct then relay, pending-record/ack,
and Badger resilience. Do not import FSE packages or its file/block sync layer.

## Data plane

Every node owns a local store behind `internal/store.Store`.

| Backend | Role |
| --- | --- |
| BadgerDB v4 | Preferred production baseline |
| SQLite | Reserved fallback only if a spike shows material Badger incompatibility or data-loss risk |
| Memory | Tests |

Key namespaces (separate from File-Sync-Engine's `fse/v1/`):

| Prefix | Replication | Contents |
| --- | --- | --- |
| `rmm/v1/private/` | never | local identity secret material |
| `rmm/v1/trust/` | never as raw tables | trusted peer public keys |
| `rmm/v1/intent/` | mesh protocol only | ManagementIntents |
| `rmm/v1/receipt/` | mesh protocol only | durable receipts |
| `rmm/v1/audit/` | local | redacted audit events |
| `rmm/v1/inventory/` | mesh protocol only | endpoint inventory |
| `rmm/v1/desktop/` | local + signed policy | desktop authorization mode, never passwords |
| `rmm/v1/enroll/` | local | consumed enrollment (token hash only), revocation |
| `rmm/v1/artifact/` | mesh after independent verify | signed release envelopes (any OS/arch) |
| `rmm/v1/update/` | local | apply receipts / rollback notes |
| `interop/mgmt/v1/` | optional, signed+encrypted | management records intentionally shared with FSE |

Raw Badger directories, SST files, and WAL files are **never** shared with
File-Sync-Engine. Backup/export is an RMM-owned stream. Validation walks keys
and known record schemas. Corrupt opens quarantine the directory and recover
from backup or empty+audit, never by merging another product's files.

## Intent plane

A `ManagementIntent` is the unit of remote work. It is durable and idempotent.

Lifecycle (strict, allowed transitions only):

```
queued → routed → received → validated → applying → succeeded|failed → acknowledged
```

Origin (usually console) owns `queued`, `routed`, and `acknowledged`.
Target (usually agent) owns `received` through `succeeded`/`failed` and emits
the ack the origin records.

Duplicate `ID` or `IdempotencyKey` must not re-apply a terminal success; the
target re-sends the existing receipt.

Command execution is a first-class intent kind but is **disabled** until a later
signed policy/authz milestone. The foundation must still persist, validate, and
fail that kind durably rather than executing attacker-controlled programs.

## Remote desktop

See `docs/REMOTE_DESKTOP.md`. Capture/encode backends are later work; the
authorization contract is in force now. No unauthenticated public listener.

## Native OS integrations (not a generic web plane)

| Area | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Inventory | os-release, kernel, arch | Win32 inventory | Darwin inventory |
| Init/service | systemd / sysv / openrc detection | Service Control Manager | launchd |
| Session | loginctl / XDG, X11 **and** Wayland | WTS / UAC session | Aqua / launchd session |
| Packages | distro-aware (apt/dnf/zypper/pacman later) | MSI/Winget later | pkg/brew later |
| Desktop | X11 + Wayland capture later | DXGI/WGC later | ScreenCaptureKit later |

This milestone implements detection and contracts, not full package/desktop
backends.

## Mesh routing (management traffic)

Prefer:

1. Direct local/LAN
2. Direct WAN
3. VPN/overlay
4. Trusted relay or tunnel (control-plane only; may be slow)

Bulk remote-desktop pixels later follow a separate path policy and still require
the same session authentication. Relays never see plaintext intents or desktop
frame payloads.

## What this milestone must prove

1. Badger opens, persists namespaced keys, reopens, exports, validates, and
   quarantines on the development host (`CGO_ENABLED=0` included).
2. Two nodes with mutual trust complete `queued → … → acknowledged` over an
   encrypted session for an inventory intent.
3. An untrusted node is refused a session.
4. A desktop-mode change to unattended without an ephemeral admin proof fails,
   and the password never appears in the store, export, or audit log.
5. Installers embed an identity-signed enrollment grant with a unique
   revocable grant ID, configurable allowed-use (exactly-one, finite N, or
   unlimited), scoped network, and no private keys.
6. Native GUI console prefers a local trusted agent mesh or starts built-in
   mesh, exposes authenticated mesh status, authorizes management intents
   before delivery, and refuses to apply agent intents.
7. Signed artifacts can be cached/exchanged (including foreign OS) and only
   applied after independent publisher verification.
