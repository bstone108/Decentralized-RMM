# Stack decision

Date: 2026-08-31  
Decision: **Go 1.22 + BadgerDB v4** as the native cross-platform foundation.

This is not a language-preference note. It is the smallest stack that can
satisfy the product constraints with evidence.

## Constraints that drove the choice

- Native console and agents on Windows, Linux, and macOS (not a web-only plane)
- BadgerDB as the preferred local durable store, behind an interface
- Ed25519 / X25519 / AEAD in-process without a managed runtime
- Same-host conceptual reuse of File-Sync-Engine identity/mesh/store *ideas*
  without importing its file/block layer or sharing its tables
- Cross-compilation from Linux CI
- Windows 7+ only **where support is safe**

## Language: Go 1.22

| Option | Verdict |
| --- | --- |
| C# / .NET Framework 4.6.1 Windows Service | Abandoned. Not native on Linux/macOS; old skeleton is empty. |
| C# / modern .NET | Cross-platform, but BadgerDB is a Go library; FSE concepts live in Go. Extra interop tax. |
| Rust | Strong native story; Badger is not first-class; slower foundation spike. |
| **Go 1.22** | **Selected.** Native binaries, Badger v4, `crypto/ecdh` X25519, easy GOOS/GOARCH matrix. |

The sandbox compiler is `go1.22.2 linux/amd64`. Module `go` version is `1.22.0`
so CI and the sandbox match without requiring Go 1.25 (FSE's current pin).

### Windows floor (safe support)

Go 1.21+ **dropped Windows 7 / 8.1 / Server 2012**. Those OS versions are also
past Microsoft's security servicing for mainstream use.

**Supported Windows: Windows 10 (1607+) and Windows Server 2016+.**  
Windows 7 is not a safe support target for this toolchain. If a future fork
must run on Windows 7, it would need a frozen Go 1.20 toolchain and is out of
scope here.

macOS: 10.15+ as implied by Go 1.22. Linux: glibc and musl via `CGO_ENABLED=0`
static binaries for the agent/console core.

## Store: BadgerDB v4 behind `store.Store`

File-Sync-Engine locked BadgerDB as its production metadata default on
2026-06-04 after same-host benchmarks; SQLite/Pebble remain fallbacks only for
catastrophic Badger failure. RMM independently needs an embedded, concurrent,
key-prefixed store.

| Option | Verdict |
| --- | --- |
| **Badger v4.2.0** | **Selected baseline.** Key prefixes give RMM-private vs interop isolation. Backup/Load APIs exist. Works with `CGO_ENABLED=0`. |
| SQLite | Reserved fallback in the store interface if this spike or later ports show material reliability issues. Not used for primary data. |
| Sharing FSE's Badger directory | **Forbidden.** Separate process, path, and prefixes. |
| rqlite / IPFS | Abandoned with the old README. |

RMM prefixes: `rmm/v1/` and `interop/mgmt/v1/`. FSE uses `fse/v1/`. Those
keyspaces must never be mixed in one database file.

## Crypto and transport

- Identity: Ed25519 (`crypto/ed25519`)
- Session agreement: X25519 (`crypto/ecdh`)
- Session AEAD: XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`)
- KDF: HKDF-SHA256 (`golang.org/x/crypto/hkdf`)
- Framing: length-prefixed over TCP for the two-node proof; interface accepts
  any `net.Conn` / stream so relays/tunnels/pipes can be added without a second
  protocol

libp2p/DHT is deferred. Discovery seams exist so those routes can be added
without granting trust.

## GUI later

Native GUI (Wails or OS toolkits) is **not** this milestone. The CLI and agent
are the native control plane. A web UI must not become the only operator path.

## Spike evidence

The automated spike is `go test ./internal/store ./internal/spike -count=1`.
It must show, on this host, with `CGO_ENABLED=0`:

1. Open, put namespaced keys, close, reopen, get
2. Export/import round-trip
3. Validation rejects `fse/v1/` keys
4. Corrupt/open-failure quarantine path
5. 1000 intent-sized records persist

Fill in measured results after the spike run:

```
host: (filled by spike)
go: (filled by spike)
CGO_ENABLED: 0
badger open+1000 put+reopen: (filled by spike)
result: (filled by spike)
sqlite fallback triggered: no
```
