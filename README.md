# Decentralized-RMM

Native, cross-platform remote management: a console and agents with local
durable state, a trusted mesh, desired-state jobs, and remote desktop. There is
no central SaaS control plane and no unauthenticated public desktop listener.

This repository has been restarted on a **Go + BadgerDB** foundation. The old
Windows Service / .NET Framework skeleton and its rqlite / rhinodht / IPFS notes
are abandoned reference material under `archive/dotnet-windows-service/`.

## Current milestone

Foundation, not a shipped product:

- Architecture, threat, protocol, and remote-desktop contracts in `docs/`
- Cross-platform stack decision evidenced by a BadgerDB spike (`docs/STACK_DECISION.md`)
- Authenticated two-node durable `ManagementIntent` lifecycle with ack
- Namespaced local store (`rmm/v1/*`) plus a separate signed/encrypted interop schema
- Linux distro / init / session (X11 and Wayland) inventory detection

Run the proof:

```bash
go test ./...
go test -count=1 ./internal/node -run TestTwoNodeAuthenticatedIntentAck -v
```

## Roles

| Binary | Role |
| --- | --- |
| `rmm` | Same native binary; `--role console`, `--role agent`, or `dual` |

Installation of the agent asks whether Remote Desktop is **unattended** or
**authorization required every session**. Changing authorization-required to
unattended over the mesh needs an ephemeral target admin/root proof that is
never persisted, logged, or replicated. If no usable admin password exists, that
change requires direct local access.

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
