# Foundation checkpoint

Updated by the dedicated Decentralized-RMM cloud agent. If Cursor usage capacity
halts work, this file is the durable resume point. Hermes: do not retry solely
because a run stopped after writing this checkpoint; wait for usage reset.

## Branch

`cursor/decentralized-rmm-cross-platform-mesh-foundation-70a2` (from `master`)

## Done in this run (keep current)

- Archived .NET Framework Windows Service skeleton under
  `archive/dotnet-windows-service/` with a NOTICE that rqlite/rhinodht/IPFS are
  abandoned.
- Binding contracts: `docs/ARCHITECTURE.md`, `THREAT_MODEL.md`, `PROTOCOL.md`,
  `REMOTE_DESKTOP.md`, `STACK_DECISION.md`, `INTEROP.md`.
- Go module `github.com/bstone108/Decentralized-RMM` (Go 1.22).
- Store interface + Badger backend + memory backend; namespaces; backup;
  validation; quarantine.
- Identity, trust, session crypto, framed protocol, intent state machine,
  desktop elevation policy, Linux inventory (X11/Wayland/distro/init),
  interop envelope, CLI `rmm`.
- Authenticated two-node durable intent/ack test.
- CI, CodeQL, and govulncheck workflows.

## Spike / proof commands

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go test ./internal/spike ./internal/store -count=1 -v
CGO_ENABLED=0 go test ./internal/node -run TestTwoNodeAuthenticatedIntentAck -count=1 -v
```

Local evidence on this agent host (2026-08-31):

- `CGO_ENABLED=0 go test ./...` — pass after docs-contract phrase fix
- Badger spike: linux/amd64, go1.22.2, 1000 intent records open/put/reopen in 113ms, export 105025 bytes, quarantine-on-corrupt MANIFEST pass, SQLite fallback not selected
- `TestTwoNodeAuthenticatedIntentAck` — pass: trusted inventory intent queued→acknowledged, durable across Badger reopen, untrusted dial refused, command.run fail-closed, remote unattended upgrade requires ephemeral admin proof that is absent from both stores
- `rmm host-info` on this host: Ubuntu 24.04, kernel 6.12, displayServer=x11
- Local `govulncheck` on go1.22.2 reports stdlib CVEs fixed in later Go patch/minor releases plus a Badger-transitive glog issue; glog was bumped to v1.2.4. CI security job scans with current stable Go.
- GitHub on `251b833`: Go tests, six-platform cross-compile, CodeQL Analyze Go, and govulncheck all succeeded. Follow-up commit adds redacted durable audit events plus `rmm listen` / `rmm intent`.

## Not done (next ordered work)

1. OS-backed remote-desktop capture (X11, Wayland portal, Windows GCDP, macOS
   ScreenCaptureKit) inside the existing session contract.
2. Real package/service apply backends per distro and OS.
3. Production DHT/relay transports (still trust-before-connect).
4. Native GUI console (not web-only).
5. At-rest encryption of Badger.
6. Do **not** sign, notarize, tag, or publish releases as part of foundation.

## Blockers

None recorded at first write. If a blocker appears, replace this paragraph with
the exact command, error, and what was already committed.
