# Foundation checkpoint

Updated after the follow-up brief: identity-provisioned installers, split
console/agent/pack binaries, local-agent mesh reuse, and independently verified
self-update / artifact cache.

## Branch

`cursor/decentralized-rmm-cross-platform-mesh-foundation-70a2` (from `master`)

## Architecture change

Each installer grant has a unique revocable grant ID and configurable
allowed-use (exactly-one, finite N, unlimited) with atomic consume, per-use
receipts, and signed mesh revocation. Dual-role `rmm` stays withdrawn.

## Proof commands

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go test ./internal/spike ./internal/store -count=1 -v
CGO_ENABLED=0 go test ./internal/node -run TestTwoNodeAuthenticatedIntentAck -count=1 -v
```

Do **not** sign, notarize, tag, or publish releases from this work.
