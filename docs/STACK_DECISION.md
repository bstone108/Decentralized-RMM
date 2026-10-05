# Stack decision

Date: 2026-08-31  
Decision: **Go 1.26 + BadgerDB v4** as the native cross-platform foundation.

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

## Language: Go 1.26

| Option | Verdict |
| --- | --- |
| C# / .NET Framework 4.6.1 Windows Service | Abandoned. Not native on Linux/macOS; old skeleton is empty. |
| C# / modern .NET | Cross-platform, but BadgerDB is a Go library; FSE concepts live in Go. Extra interop tax. |
| Rust | Strong native story; Badger is not first-class; slower foundation spike. |
| **Go 1.26** | **Selected.** Native binaries, Badger v4, `crypto/ecdh` X25519, easy GOOS/GOARCH matrix. |

The sandbox compiler is `go1.26.8 linux/amd64`. Module `go` version is `1.26.0`
with `toolchain go1.26.8`. That is the minimum language version required by
the patched `golang.org/x/crypto` and `golang.org/x/net` modules, on the
latest Go 1.26 patch. CI installs the same toolchain.

### Windows floor (safe support)

Go 1.21+ **dropped Windows 7 / 8.1 / Server 2012**. Those OS versions are also
past Microsoft's security servicing for mainstream use.

**Supported Windows: Windows 10 (1607+) and Windows Server 2016+.**  
Windows 7 is not a safe support target for this toolchain. If a future fork
must run on Windows 7, it would need a frozen Go 1.20 toolchain and is out of
scope here.

macOS: 12 Monterey or later, as implied by Go 1.26 (Go 1.27 will require
macOS 13). Linux: glibc and musl via `CGO_ENABLED=0`
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

### At-rest encryption

New stores are encrypted with Badger's built-in AES-256 (`EncryptionKey` of
32 bytes) and a 64 MiB index cache. Encryption requires a block cache; the
Badger default (256 MiB) is left in place so decrypted blocks are not re-read
from disk on every lookup. This works with `CGO_ENABLED=0` on Linux, Windows,
and macOS. The logical `Export` stream stays a decrypted backup and is still
rejected when it contains `fse/v1/` keys or password fields. The at-rest key
is not part of that stream.

**Key file.** On first open of a new or still-plaintext store, the process
generates a random 32-byte key and writes `rmm-badger-key-v1` plus standard
base64 to a sibling of the store directory: `<data>/rmm.badger.key` next to
`<data>/rmm.badger`. The file mode is `0600`. On Windows the DACL is replaced
with an owner-only ACE that does not inherit broader permissions from the
parent. The key is never logged and never written into the Badger directory,
so a copy of `rmm.badger` is not enough to read the data.

**Override.** `--store-key-file PATH` on `rmm-agent`, `rmm-console`, and
`rmm-pack` wins. Otherwise `RMM_STORE_KEY_FILE` is used when set. An empty
override keeps the sibling default.

**Backup.** Copy the key file offline, separately from the data directory, and
treat it like the node identity. Restoring a machine needs both the store
directory and that key (via the default path, the env var, or the flag).
Badger rotates internal data keys under this same master key; operators do
not manage those. **Losing the master key makes the store permanently
unreadable.** There is no escrow and no password recovery.

**Existing plaintext stores** are migrated in place on the next open:

1. The original directory is only opened read-only.
2. Entries are streamed into a sibling `rmm.badger.enc-new` encrypted with the key.
3. Every user-visible key/value (all versions, count plus SHA-256) is compared.
4. Only after that match is the original renamed to `rmm.badger.plaintext-backup` and the encrypted directory renamed into place. A crash between those renames is finished on the next open.
5. The encrypted store is opened again and the checksum is compared to the plaintext backup. **The plaintext copy is then deleted.** It is not kept: leaving it on disk would undo at-rest encryption. Deletion is a normal recursive remove, not a multi-pass wipe.

A verification failure deletes the partial encrypted sibling immediately. A crash during the copy leaves that sibling; the next open discards it and starts again. In both cases the original plaintext directory stays where it was and remains readable. A checksum mismatch after the swap leaves both directories on disk and refuses to start, so the original is not destroyed. A wrong or missing key on an already encrypted store returns a clear error and does not quarantine or rewrite the directory. Corrupt opens that are not key mismatches still quarantine the directory, as before. The key file lives outside the store, so quarantine does not take it.

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

## Native GUI (CGO-free)

The product console is a native GUI, not a TUI and not a mandatory web console.
Toolkit choice is constrained by `CGO_ENABLED=0` and Linux-hosted
cross-compilation of `rmm-console` for Windows, Linux, and macOS:

| OS | Adapter | Why |
| --- | --- | --- |
| Windows | Win32 `MessageBoxW` (user32) | Real GUI; no CGO; compiles from Linux |
| Linux | X11 window + zenity/kdialog dialogs | Real GUI; Wayland-only is documented as needing X11/`DISPLAY` |
| macOS | Aqua via `osascript` | Real GUI; no CGO; compiles from Linux |

Wails, Fyne, and Gio are not used: they require CGO and/or cannot cross-compile
darwin/windows GUI from Linux CI. `internal/consoleui` stays a POLICY.txt
presenter; `internal/consolegui` is the GUI control plane (mesh status +
management-intent authorization).

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
host: linux/amd64 (Ubuntu 24.04, go1.26.8)
go: go1.26.8
CGO_ENABLED: 0
badger open+1000 put+reopen: 388ms
export size: 104953 bytes
validation: pass (rejects fse/v1/ keys and password fields)
quarantine on corrupt MANIFEST: pass
result: Badger selected; no material compatibility/reliability trouble on this host
sqlite fallback triggered: no
```
