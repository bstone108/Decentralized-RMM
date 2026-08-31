# Security

Report issues privately to the repository owner. Do not file public PoCs for
remote code execution, authentication bypass, or desktop-session bypass.

Binding documents:

- `docs/THREAT_MODEL.md`
- `docs/PROTOCOL.md`
- `docs/REMOTE_DESKTOP.md`
- `docs/INTEROP.md`

Non-negotiable reminders:

- Discovery is not trust.
- No unauthenticated public desktop listener.
- Admin/root passwords used for remote unattended enablement are ephemeral
  only: never persist, log, or replicate.
- Do not share raw Badger files with File-Sync-Engine.
- `command.run` fails closed in this foundation.
