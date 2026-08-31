# Remote desktop contract

Status: **binding authorization and transport contract**. Pixel capture, encode,
and input injection are later OS-backed work. Shipping a viewer that ignores
this document is a vulnerability.

## Modes

Chosen **at agent installation**, stored as `rmm/v1/desktop/policy` (mode only):

| Mode | Viewer is a trusted mesh peer | Interactive user on target |
| --- | --- | --- |
| `unattended` | sufficient | not asked each session |
| `authorization-required` | necessary but not sufficient | must approve **every** session |

Default if the installer is non-interactive without a flag: `authorization-required`.

## No public desktop listener

Forbidden:

- Binding RFB/VNC/RDP/SPICE/websocket viewer ports to `0.0.0.0` without the
  RMM session handshake
- "Anyone with the link" desktop URLs
- Sharing a static desktop password as the only gate

Required:

- Desktop bytes (when implemented) move inside an already-authenticated
  `rmm-hello-v1` session, or a child stream derived from that session.
- Relays may forward ciphertext. Relays must not see frame plaintext.

## Session request (v1 messages)

`desktop_request`: viewer node ID, requested mode, intent ID.

`desktop_decision`: `allowed`, `reason`, `mode`.

Evaluation order:

1. Viewer identity is a trusted peer (session already proved this).
2. If policy is `authorization-required`, wait for local user consent. If no
   interactive session exists (no X11/Wayland/Aqua/Win32 user), deny unless
   policy is `unattended`.
3. If policy is `unattended`, allow the trusted viewer.

## Changing mode remotely

`desktop.mode.change` payload: `{ "mode": "unattended" | "authorization-required" }`.

Downgrade to `authorization-required` is allowed from a trusted console without
an extra OS password (it reduces remote power).

Upgrade to `unattended`:

1. Prefer an **ephemeral admin/root proof** supplied with the intent:
   username + password (or platform equivalent).
2. The agent hands the secret to an OS verifier (`internal/desktop.Verifier`).
3. On success or failure, **zero** the secret in memory.
4. Persist only the resulting mode and a redacted receipt (`elevationUsed: true`,
   never the password).
5. If the verifier reports that no usable admin password exists, refuse unless
   `localAccess: true` (the caller is the already-elevated local installer /
   console on the same host). Remote callers cannot set `localAccess`.

## Linux display servers

Inventory must report:

- `displayServer`: `x11`, `wayland`, `none`, or `both` (XWayland present)
- `sessionType`: from XDG or loginctl when available
- `graphicalSessionUser` when detectable

Later capture:

- X11: MIT-SHM / XDamage path (never a system-wide open XTCP without auth)
- Wayland: wlr-screencopy, xdg-desktop-portal, or compositor-specific protocol
  with user consent when policy requires it

A Wayland session must not silently fall back to capturing a different user's
X11 display.

## Windows and macOS (later backends, current policy)

- Windows: capture via Graphics Capture / DXGI in the right session isolation
  (service vs user session). Unattended mode implies the agent is installed
  with enough rights to create a user-session capture helper. UAC elevation
  for mode change follows the ephemeral-proof rule.
- macOS: ScreenCaptureKit + TCC. Unattended mode still cannot bypass TCC
  without the install-time grant; the policy records whether that grant exists.

## Installer prompt (required copy)

The installer MUST ask, in the OS's native UI or TTY:

```
Remote Desktop access
  [ ] Unattended (trusted consoles may view without asking a user each time)
  [ ] Authorization required every session (default)
```

Changing this later remotely is the elevation flow above, not a hidden flag.
