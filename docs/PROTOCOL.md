# Protocol

Status: **v1 foundation**. Transport-agnostic framed messages over any reliable
byte stream (TCP now; pipe/stdio, relay, tunnel, or libp2p stream later).

## Framing

Unencrypted (handshake only) and encrypted (post-hello) frames:

```
uint32be length | payload
```

`length` is the payload size, max **1048576** bytes (1 MiB). Larger frames are
a protocol error and tear down the session.

Handshake payloads are JSON. Post-hello payloads are
**XChaCha20-Poly1305** ciphertexts whose plaintext is JSON.

## Handshake

Both sides send `hello` then verify the peer before deriving session keys.

Hello fields:

- `protocolVersion` (must be 1)
- `nodeID` (`rmm1:` fingerprint)
- `role` (`console` | `agent`)
- `publicKey` (Ed25519, standard Base64)
- `sessionPublicKey` (X25519, standard Base64)
- `encryptionLevel` (minimum accepted 4; see table)
- `nonce` (32 random bytes, standard Base64)
- `capabilities` (sorted unique strings)
- `signature` (Ed25519 over the canonical hello transcript)

Transcript:

```
rmm-hello-v1
<nodeID>
<role>
<publicKey>
<sessionPublicKey>
<encryptionLevel decimal>
<nonce>
<capabilities joined by comma>
```

Verification:

1. Decode keys; reject wrong lengths.
2. Verify signature with `publicKey`.
3. Confirm `nodeID` matches fingerprint(`publicKey`).
4. Confirm `publicKey` is in the **local trust store**. If not, send `error`
   `untrusted_peer` and close. Do not derive keys. Do not log the peer as
   paired.
5. Confirm `protocolVersion == 1`.
6. Confirm `encryptionLevel >= 4` for non-debug builds. Level 0 is refused on
   any non-loopback debug override that is not explicitly compiled in tests.

Key schedule (both sides, after mutual verify):

```
shared = X25519(localSessionPriv, remoteSessionPub)
salt   = nonce_min || nonce_max   (lexicographic order of the two nonces)
PRK    = HKDF-SHA256-Extract(salt, shared)
OKM    = HKDF-SHA256-Expand(PRK, "rmm-session-v1", 80 bytes)
k_cs   = OKM[0:32]    // console→agent or the side with lower nodeID → other
k_sc   = OKM[32:64]
n_cs   = OKM[64:72]
n_sc   = OKM[72:80]
```

The sender with the lexicographically lower `nodeID` uses `k_cs` to send.
Nonces are 24 bytes: 16-byte derived prefix (HKDF info `"rmm-nonce-v1"` +
direction) || uint64be counter starting at 1. Counters must be monotonic;
gaps are errors.

## Encryption levels

Aligned in *policy* with File-Sync-Engine so operators can reason across
products, but this protocol is `rmm-hello-v1`, not `fse-peer-hello-v1`.

| Level | Profile | This milestone |
| --- | --- | --- |
| 0 | none-debug | tests only; refused otherwise |
| 4 | strong (X25519, HKDF-SHA256, XChaCha20-Poly1305) | **required default** |
| 5–7 | tighter rekey | accepted if both advertise |
| 8–10 | hybrid KEM planned | not implemented; negotiate down to 4–7 |

## Message types

| Type | When | Purpose |
| --- | --- | --- |
| `hello` | handshake | identity + session key |
| `error` | any | `{code, message}` redacted |
| `intent` | trusted session | one ManagementIntent |
| `intent_ack` | trusted session | receipt for one intent |
| `inventory` | trusted session | inventory snapshot |
| `peer_exchange` | trusted session | candidate addresses only |
| `desktop_request` | trusted session | RD session request |
| `desktop_decision` | trusted session | allow/deny + mode |
| `interop_record` | trusted session | signed+encrypted `interop/mgmt/v1` envelope |
| `artifact_offer` | trusted session | cached signed-release **metadata** only |
| `artifact_request` | trusted session | request one envelope by component/version/os/arch |
| `artifact_chunk` | trusted session | slice of a signed envelope; recipient re-verifies |

Unknown types are errors. Exactly one payload field must match `type`.

## ManagementIntent

```json
{
  "id": "uuid-v4",
  "idempotencyKey": "stable-key",
  "originNodeID": "rmm1:…",
  "targetNodeID": "rmm1:…",
  "kind": "inventory.collect",
  "payload": {},
  "createdAt": "RFC3339",
  "status": "queued"
}
```

Kinds in v1:

| Kind | Apply in this milestone |
| --- | --- |
| `inventory.collect` | yes — return host snapshot |
| `config.apply` | validate schema; stub apply |
| `app.install` `app.update` `app.remove` `app.verify` | validate; stub |
| `service.control` | validate; stub |
| `command.run` | **fail closed** |
| `desktop.session.request` | policy decision; no pixels yet |
| `desktop.mode.change` | policy + ephemeral elevation rules |

### Lifecycle

| Status | Owner | Meaning |
| --- | --- | --- |
| `queued` | origin | durable, not yet on the wire |
| `routed` | origin | placed on a trusted session |
| `received` | target | persisted locally |
| `validated` | target | schema + authz passed |
| `applying` | target | side effects in progress |
| `succeeded` | target | terminal success |
| `failed` | target | terminal failure (`lastError` required) |
| `acknowledged` | origin | origin persisted the receipt |

Allowed transitions are only forward along that path, except `validated` /
`applying` may go to `failed`. No skipping `received` or `validated`.
Re-delivery of a terminal intent re-emits `intent_ack` and does not re-enter
`applying`.

## Peer exchange

After trust, peers may send addresses they know. Receivers treat them as
**untrusted candidates**. They do not grant relay rights.

## Size and denial

1 MiB max, handshake timeout 10s, idle session timeout implementation-defined
(foundation tests use a few seconds). There is no anonymous banner beyond
closing the TCP connection on handshake failure.
