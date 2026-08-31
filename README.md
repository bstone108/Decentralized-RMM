# Decentralized-RMM

Native, cross-platform remote management: a separately deployable console and
agents, identity-provisioned installers, a trusted mesh, desired-state jobs,
remote desktop, and independently verified self-update. There is no central
SaaS control plane and no unauthenticated public desktop listener.

This repository has been restarted on a **Go + BadgerDB** foundation. The old
Windows Service / .NET Framework skeleton and its rqlite / rhinodht / IPFS notes
are abandoned reference material under `archive/dotnet-windows-service/`.

Cursor's earlier dual-role `rmm` binary is obsolete. Console, agent, and packager
are separate native programs.

## Current milestone

- Architecture, threat, protocol, enrollment, deployment, console, and
  self-update contracts in `docs/`
- Cross-platform stack decision evidenced by a BadgerDB spike (`docs/STACK_DECISION.md`)
- Authenticated two-node durable `ManagementIntent` lifecycle with ack
- Identity-signed enrollment manifests and platform-native installer trees
- Console local-agent mesh reuse vs built-in mesh
- Signed artifact cache/exchange (including other OS/arch) with independent verify
- Namespaced local store (`rmm/v1/*`) plus a separate signed/encrypted interop schema

Run the proof:

```bash
go test ./...
go test -count=1 ./internal/node -run TestTwoNodeAuthenticatedIntentAck -v
```

## Roles

| Binary | Role |
| --- | --- |
| `rmm-agent` | Platform agent (endpoint management). No operator GUI. |
| `rmm-console` | Operator console / mesh peer. No agent function. No TUI/web console. |
| `rmm-pack` | Corporate/mass identity-provisioned installer builder |
| `rmm` | `host-info` helper only |

When a trusted platform agent runs on the same computer, the console prefers a
local authenticated connection and reuses that agent's mesh; otherwise it starts
its own built-in authenticated mesh.

Installation of the agent asks whether Remote Desktop is **unattended** or
**authorization required every session** (also as a signed enrollment flag).
Changing authorization-required to unattended over the mesh needs an ephemeral
target admin/root proof that is never persisted, logged, or replicated.

## File-Sync-Engine

Interoperability with File-Sync-Engine is **optional and separate**. The two
products may discover each other; discovery grants nothing. A connection or
reciprocal relay/tunnel is allowed only after cryptographic verification of a
shared trusted identity. RMM does not import FSE's file/block sync layer and
does not share raw Badger tables or files with it.

See `docs/INTEROP.md`.

## Supported platforms

- Linux (distro-aware packages, layout, service, session)
- macOS
- Windows 10+ / Windows Server 2016+ (safe current-Go floor; see `docs/STACK_DECISION.md`)

Do not sign, notarize, tag, or publish releases from this foundation work.
