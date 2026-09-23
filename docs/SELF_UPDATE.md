# Secure self-update

Status: **binding**. Where platform and admin/enrollment policy permit, every
RMM component (`rmm-agent`, `rmm-console`, `rmm-pack`) uses the same update
pipeline.

## Source and cache

A trusted **release artifact** may be fetched from GitHub (or another release
source) and cached under `rmm/v1/artifact/`. Authenticated mesh/LAN peers may
exchange cached envelopes, including **foreign OS** / architecture artifacts they
will not apply locally, so other machines skip repeated Internet downloads.

Peers **cannot introduce untrusted updates**. `AcceptFromPeer` requires the
envelope to verify against the enrollment **publisher** public key, not the
sending peer's key.

Each recipient verifies the publisher independently: signature, hash, version
policy, OS/arch (on apply), and expiry.

## Pipeline

`discover → download → verify → stage → apply → OS-native restart → reconnect → receipt`

On apply failure: restore `.bak`, persist a failed receipt, do not take a
peer-supplied binary that failed verification.

OS-native adapters (commands are planned, not blindly executed by the library):

| OS | Adapter |
| --- | --- |
| Linux | systemd `systemctl restart` |
| macOS | launchd `kickstart` |
| Windows | Service Control Manager `sc.exe` |

Restart is followed by authenticated mesh reconnect (service `Restart=` /
relisten). Receipts live under `rmm/v1/receipt/` and `rmm/v1/update/`.

Enrollment flag `selfUpdate=false` disables apply. Missing publisher identity
disables ingest.
