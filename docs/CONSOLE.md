# Console

Status: **binding** process and UX contract.

## Separately deployable mesh peer

`rmm-console` is native on Windows, Linux, and macOS. It is an authenticated
mesh peer with its own identity, DHT/routing **candidates**, local and peer
discovery, relay/tunnel **path planning**, and secure artifact-cache exchange.

The console has no endpoint-management agent function: it must not apply
inventory, command, desktop, service, or package intents. `HandleIntent` fails
closed on a console node.

The product console is not a terminal/TUI and not a mandatory web-console
substitute. Policy visibility uses `POLICY.txt` plus an OS dialog when the
desktop session provides one (`zenity` / `osascript`). A later native GUI may
consume the same `consoleui.Presenter`; it remains separately deployable from
the agent.

## Same-computer agent preference

When a compatible trusted **platform agent** is running on the same computer:

1. The agent writes `local.advertise.json` (mode 0600) next to its data dir.
2. Discovery of that file still grants nothing.
3. The console checks that the advertised node ID and public key are already
   in its trust store and that the role is `agent`.
4. If so, GUI/CLI **prefers a local authenticated connection** and **does not**
   start its own mesh listener; it reuses that agent's mesh/network presence.

Otherwise the console starts its **own built-in authenticated mesh** listener.

## Operator surface

```bash
rmm-console run --data ~/.rmm-console --agent-data /var/lib/rmm
rmm-console policy --manifest enrollment.manifest.json
rmm-console intent --addr HOST:PORT --target rmm1:... --kind inventory.collect
```
