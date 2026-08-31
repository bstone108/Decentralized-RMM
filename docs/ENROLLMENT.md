# Enrollment

Status: **binding**. Identity-provisioned installers carry an **identity-signed
enrollment manifest**, not merely a code-signed binary.

## Grant contract

Each installer grant has a **unique revocable grant ID** (`grantID`). That ID
is the revocation handle. Allowed-use is an explicit mode and value:

| Mode | Meaning |
| --- | --- |
| `exactly-one` | a single enrollment use |
| `finite` | any operator-defined positive count `N` |
| `unlimited` | no use cap (still scoped, expiring, and revocable) |

The signed manifest also binds:

- intended identity public material (issuer/publisher Ed25519 + box key)
- scoped bootstrap peers and connection details
- target org, OS, architecture, and policy flags
- expiry
- authorized build-time flags (desktop mode including unattended remote
  desktop, self-update permission)
- SHA-256 of the grant credential (never the raw credential in durable store)

The installer tree also contains `POLICY.txt` so both the native installer and
the console can show operators exactly what they are authorizing, including
grant ID and allowed-use mode.

## Consume

Consume verifies signature, grant credential, expiry, revocation, OS/arch, and
CIDR-scoped network policy, then **atomically** takes one use from the ledger
and writes a durable per-use receipt and audit event for **every** mode
(including unlimited). A node that has already applied the grant does not take
another use on restart.

Revocation or retirement of the grant **prevents future enrollments** and is
published as an issuer-signed mesh notice. Historic receipts and audit records
are retained.

```bash
rmm-pack build ... --uses exactly-one
rmm-pack build ... --uses finite:25
rmm-pack build ... --uses unlimited
rmm-console revoke --grant grant:… --reason retired
```

## Independent verification

`rmm-pack verify --dir TREE` checks the manifest signature and grant credential
match without trusting the rest of the tree.

## Forbidden installer contents

Installers MUST NOT embed (never embed):

- reusable private keys or issuer seeds
- passwords or other unrestricted credentials
- unrestricted network access (`0.0.0.0/0`, `::/0`, or missing CIDRs)

Bootstrap addresses must fall inside `allowedCIDRs`. DHT and relay flags only
authorize **candidate discovery**; discovery still grants nothing.
