# Foundation checkpoint

Updated after the installer enrollment-policy correction: allowed-use is
configurable (**one**, any finite operator-defined `N`, or **explicitly
unlimited**). One-time enrollment is an option, not a requirement. Dual-role
stays withdrawn. The native GUI console (mesh status and management-intent
authorization), FSE isolation, and no-release constraints are unchanged.

## Branch

`cursor/decentralized-rmm-cross-platform-mesh-foundation-70a2` (from `master`)

## Architecture change

Each generated installer/enrollment grant has a unique revocable grant ID.
Scope, expiry, revocation, and per-use receipts/audit stay enforceable for
every allowed-use mode. Console operators can retire/revoke a grant, publish
the issuer-signed notice on the mesh, block future enrollment, and keep
historic evidence. Installers never embed reusable private keys or
unrestricted credentials.

## Proof commands

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go test ./internal/enroll ./internal/pack ./internal/node -count=1 -v -run 'Use|Grant|Revoke|Enroll|Finite|Unlimited|Atomic|ParseUses|Unique'
CGO_ENABLED=0 go test ./internal/consolegui ./internal/consolemesh -count=1
```

Do **not** sign, notarize, tag, or publish releases from this work.
