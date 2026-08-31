# Enrollment

Status: **binding**. Identity-provisioned installers carry an **identity-signed
enrollment manifest**, not merely a code-signed binary.

## What the manifest binds

The issuer (typically a console identity) signs:

- intended identity public material (issuer/publisher Ed25519 + box key)
- scoped bootstrap peers and connection details
- target org, OS, architecture, and policy flags
- expiry and a revocation identifier
- authorized build-time flags (desktop mode including unattended remote
  desktop, self-update permission)
- a SHA-256 of a one-time/scoped enrollment token (never the raw token in
  durable store)

The installer tree also contains `POLICY.txt` so both the native installer and
the console can show operators exactly what they are authorizing.

## One-time / scoped consume

`MaxUses` defaults to 1. Consume verifies signature, token, expiry, revocation,
OS/arch, and CIDR-scoped network policy, then:

1. Trusts the issuer (and listed peer public keys)
2. Applies desktop policy from flags
3. Records a use counter under `rmm/v1/enroll/`
4. Stores the **signed manifest** (token **hash** only)
5. Deletes the raw token from the endpoint data directory

A second consume of the same enrollment ID on that node is refused. Restart
loads the already-consumed record and does not require the token again.

## Independent verification

`rmm-pack verify --dir TREE` checks the manifest signature and token match
without trusting the rest of the tree. Recipients of mesh-exchanged artifacts
perform the same class of check for updates (see `docs/SELF_UPDATE.md`).

## Forbidden installer contents

Installers MUST NOT embed (never embed):

- reusable private keys or issuer seeds
- passwords or other unrestricted credentials
- unrestricted network access (`0.0.0.0/0`, `::/0`, or missing CIDRs)

Bootstrap addresses must fall inside `allowedCIDRs`. DHT and relay flags only
authorize **candidate discovery**; discovery still grants nothing.
