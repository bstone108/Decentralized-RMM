# Foundation checkpoint

Updated after the follow-up brief: identity-provisioned installers, split
console/agent/pack binaries, local-agent mesh reuse, and independently verified
self-update / artifact cache.

## Branch

`cursor/decentralized-rmm-cross-platform-mesh-foundation-70a2` (from `master`)

## Architecture change

Dual-role `rmm` is withdrawn. Live binaries are `rmm-agent`, `rmm-console`,
`rmm-pack` (plus `rmm host-info`). Console is a mesh peer with no agent
function. Enrollment is identity-signed, not merely code signing.

## Proof commands

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go test ./internal/spike ./internal/store -count=1 -v
CGO_ENABLED=0 go test ./internal/node -run TestTwoNodeAuthenticatedIntentAck -count=1 -v
```

Do **not** sign, notarize, tag, or publish releases from this work.
