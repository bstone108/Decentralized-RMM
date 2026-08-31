# Foundation checkpoint

Updated after the native GUI console contract: authenticated
local-agent-preferred mesh status and a safe management-intent authorization
workflow in a separately deployable `rmm-console` GUI (Win32 / X11 / Aqua,
`CGO_ENABLED=0`). Dual-role stays withdrawn. Enrollment grant uses and FSE
isolation are unchanged. Do not sign, notarize, tag, or publish releases.

## Branch

`cursor/decentralized-rmm-cross-platform-mesh-foundation-70a2` (from `master`)

## Architecture change

`rmm-console run` is a native GUI (not a TUI, not a mandatory web console).
Each installer grant still has a unique revocable grant ID and configurable
allowed-use (exactly-one, finite N, unlimited) with atomic consume, per-use
receipts, and signed mesh revocation.

## Proof commands

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go test ./internal/consolegui ./internal/consolemesh -count=1 -v
CGO_ENABLED=0 go test ./internal/spike ./internal/store -count=1 -v
CGO_ENABLED=0 go test ./internal/node -run TestTwoNodeAuthenticatedIntentAck -count=1 -v
```

Do **not** sign, notarize, tag, or publish releases from this work.
