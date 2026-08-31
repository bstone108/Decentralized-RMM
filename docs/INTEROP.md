# File-Sync-Engine interoperability

Status: **optional, separate, deny-by-default.**

RMM and File-Sync-Engine may run on the same machine or the same overlay. They
are different products with different data.

## What may be reused (concepts only)

From FSE, RMM reimplements — does not import — these ideas:

- Ed25519 node identity and fingerprinting
- Pairing / identity-package style trust bootstrap
- Trust-before-traffic (discovery is not authorization)
- Direct-then-relay management path preference
- Durable pending records with ack/fail receipts
- Badger key-prefix stores, backup, validation, quarantine

RMM must not copy FSE packages, must not import `filesyncengine/...`, and must
not reuse FSE file/block/manifest/pending-write schemas.

## How they may find each other

Either product may learn the other's listen address through:

- local discovery
- DHT (different namespaces: `decentralized-rmm/v1` vs `filesyncengine/v1`)
- peer exchange
- configured peers
- relays
- tunnels

**Discovery grants nothing.** Seeing an FSE node in a DHT namespace does not
allow opening an RMM session, offering a relay, or reading stores.

## When a connection is allowed

Only after **cryptographic verification of a shared trusted identity**:

1. Each side already has the other's management or interop public key in its
   trust store (manual pair, scanned package, or prior verified introduction).
2. `rmm-hello-v1` (or a future dedicated interop hello) verifies that key.
3. Only then may either side offer a reciprocal relay/tunnel for **management**
   traffic.

A shared host path or a shared operator is not a shared trusted identity.

## Interop record namespace

On-the-wire and on-disk records that are *intentionally* shared use:

```
interop/mgmt/v1/<recordType>/<id>
```

Envelope (`internal/interop.Envelope`):

- `schema`: `interop/mgmt/v1`
- `recordType`: allow-list only
- `originNodeID`, `recipientNodeID`
- `originSignature` (Ed25519 over canonical bytes)
- `ciphertext` (X25519 + XChaCha20-Poly1305 to recipient)
- `createdAt`

Allowed `recordType` values:

| Type | Purpose |
| --- | --- |
| `presence` | node ID, role, capabilities, listen candidates |
| `capability` | which management kinds this RMM node exposes |
| `intent_ref` | ID + kind + status of a management intent (no payloads with secrets) |
| `ack_ref` | ID + terminal status |

Forbidden in this namespace:

- file bytes, block bytes, content hashes as transfer objects
- FSE manifests, tombstones, folder paths
- `fse/v1/` keys
- raw Badger files
- passwords, private keys, session keys

An encoder that is asked to wrap a forbidden type must error.

## Physical isolation

| Object | RMM | FSE |
| --- | --- | --- |
| Process | `rmm` | `fse` |
| Store directory | e.g. `$DATA/rmm.badger` | e.g. `$DATA/metadata.badger` |
| Key prefix | `rmm/v1/`, `interop/mgmt/v1/` | `fse/v1/` |
| Backup stream | RMM export | FSE export |

Copying SST files between products is unsupported and must fail validation.
