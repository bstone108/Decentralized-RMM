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
- Console local-agent mesh reuse vs built-in mesh, with a native GUI that
  shows authenticated mesh status and authorizes management intents
- Signed artifact cache/exchange (including other OS/arch) with independent verify
- Namespaced local store (`rmm/v1/*`) encrypted at rest, plus a separate signed/encrypted interop schema

Run the proof:

```bash
go test ./...
go test -count=1 ./internal/node -run TestTwoNodeAuthenticatedIntentAck -v
```

## Roles

| Binary | Role |
| --- | --- |
| `rmm-agent` | Platform agent (endpoint management). No operator GUI. |
| `rmm-console` | Native GUI operator console / mesh peer. No agent function. No TUI/web console. |
| `rmm-pack` | Corporate/mass identity-provisioned installer builder |
| `rmm` | `host-info` helper only |

When a trusted platform agent runs on the same computer, the native GUI prefers
a local authenticated connection and reuses that agent's mesh; otherwise it
starts its own built-in authenticated mesh.

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

## Releases

`.github/workflows/release.yml` publishes a GitHub Release when a `v*` tag is pushed, and when the workflow is run manually with that existing tag. Signing, notarization, and publishing run on those events only.

Versions are `YYYY.MM.DD.BB` in America/Chicago. Month, day, and build are zero-padded to at least two digits: `v2026.10.04.01`, `v2026.10.05.01`.

```bash
version="$(scripts/next-date-build-version)"
# Optional: commit docs/release-notes/v${version}.md on this commit first.
git tag "v${version}"
git push origin "v${version}"
```

`scripts/next-date-build-version` reads existing `v<date>.*` tags for today in America/Chicago, including older unpadded tags such as `v2026.10.5.1`, and prints the next padded version. The workflow embeds that value with `-ldflags` (`-X main.version=YYYY.MM.DD.BB`). The release title is `v<version>`. A hyphen in the tag marks a prerelease. Notes come from `docs/release-notes/<tag>.md` on the tagged commit; otherwise GitHub generates them. The workflow does not create the tag.

Release assets are `rmm-<tag>-linux-amd64.tar.gz`, `rmm-<tag>-linux-arm64.tar.gz`, `rmm-<tag>-windows-amd64.zip`, `rmm-<tag>-windows-arm64.zip`, `rmm-<tag>-macos-arm64.zip`, `rmm-<tag>-macos-x86_64.zip`, `rmm-<tag>-macos-universal.zip`, and `SHA256SUMS`. Each archive contains the deployable binaries plus `README.md`, `SECURITY.md`, and `docs/DEPLOYMENT.md` (including at-rest key backup). macOS archives are Developer ID signed and notarized.
