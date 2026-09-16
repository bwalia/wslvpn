# Client

The CLI (`wsl`) and the agent library do two separable things: talk to the
control plane, and drive a WireGuard interface on the host. A session without an
interface carries no traffic, so `connect` does both and `status` reports both
independently.

## Prerequisites

`wg-quick` from the WireGuard tools has to be installed:

```bash
brew install wireguard-tools      # macOS
apt install wireguard-tools       # Debian/Ubuntu
```

The agent searches `PATH`, then `/opt/homebrew/bin`, `/usr/local/bin` and
`/usr/bin` — a GUI-launched process does not inherit a shell `PATH`, so the
Homebrew locations are checked explicitly. `WSL_WG_QUICK` overrides the search
with a specific path.

## Privilege

Creating a network interface needs root. The agent does not run as root, and the
desktop GUI must not, so escalation happens per command and is visible:

- running as root — `wg-quick` is invoked directly
- otherwise — the command is re-run under `sudo`, which may prompt on a terminal
- `--no-sudo` refuses escalation, and the command fails instead

There is no persistent privileged helper. That keeps the trust boundary obvious
at the cost of a password prompt on each connect.

## Lifecycle

```bash
wsl login --email you@example.com
wsl connect --network development
wsl status
wsl disconnect
```

`connect` creates the session first, then brings the interface up, because the
gateway has to know about the peer before traffic will pass. `disconnect`
reverses that order — the interface goes down before the session is released, so
there is never a window where an interface is up and pointed at a gateway that
has already dropped the peer.

If the session is created and the interface then fails to come up, the session is
left in place rather than silently revoked. `status` reports that state as
`Session open, tunnel down`; fix whatever `wg-quick` reported and run `connect`
again.

`--no-tunnel` on either command does the control-plane half only, and leaves the
interface to you. It is what to use when something else on the host already
manages WireGuard.

## What `status` reads

The connected/disconnected line comes from the operating system, not from what
the agent remembers doing:

- Linux — whether `/sys/class/net/wsl` exists
- macOS — `wg-quick` records the `utun` device it was given in
  `/var/run/wireguard/wsl.name`; the agent resolves that and checks the device

Neither needs root, so `wsl status` never prompts. `wsl diagnostics` prints the
resolved `wg-quick` path, the config path and the raw tunnel state.

## Files

| Path | Contents |
| --- | --- |
| `<data dir>/agent-state.json` | Session, device and access token — mode 0600 |
| `<data dir>/wsl.conf` | Rendered WireGuard config, including the interface private key — mode 0600 |
| `<data dir>/keys/wg.private` | Device private key — mode 0600 |

The data directory is `~/Library/Application Support/wsl-zerotrust` on macOS and
`~/.local/share/wsl-zerotrust` on Linux.

The config basename is what `wg-quick` turns into the interface name, so
`wsl.conf` and the `wsl` interface are the same decision — a test asserts they
cannot drift apart.

## Troubleshooting

**`wg-quick not found`** — install the WireGuard tools, or set `WSL_WG_QUICK`.

**`bringing the tunnel up needs root`** — run under `sudo`, or use `--no-tunnel`
and bring the interface up yourself.

**`wg-quick reported success but no interface appeared`** — `wg-quick` exited 0
without leaving a device behind. Check `wg show` as root and the system log; on
macOS a stale `/var/run/wireguard/wsl.name` from an unclean shutdown is the usual
cause.

**`status` shows `Session open, tunnel down`** — the control plane has a live
session for this device but nothing is up locally. Run `connect` again.
