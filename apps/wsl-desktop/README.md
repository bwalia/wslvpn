# WSL Zero Trust — Desktop (macOS)

A window over the `wsl` command-line tool. The GUI holds no state and performs
no privileged operation of its own: everything it shows is read back from
`wsl status --json`, and everything it does is a CLI invocation. There is one
implementation of what "connected" means, and the window cannot drift from it.

## Build, test, run

```bash
cd apps/wsl-desktop
make test     # view logic (node --test) + the CLI bridge (cargo test, clippy)
make dev      # a window over a debug build of the CLI
make app      # release bundle, with the CLI inside it
open src-tauri/target/release/bundle/macos/WSLZeroTrust.app
```

The Mac needs the WireGuard tools and a bash new enough to run `wg-quick`:

```bash
brew install wireguard-tools bash
```

Everything the window decides — which panel, which buttons, what the DNS line
says — is in `view.js`, a pure function of the CLI's JSON, and is covered by
`view.test.js`. `main.js` only applies it to the DOM.

Requires a Rust toolchain, and macOS for native builds. `src-tauri` is its own
cargo workspace — Tauri pulls in the platform webview, which the control plane
has no reason to link against and CI has no reason to install — so it builds
from that directory rather than with the rest of the repo.

Point the app at a development build of the CLI with `WSL_CLI`:

```bash
cargo build -p wsl-cli
WSL_CLI=$PWD/../../target/debug/wsl npm run tauri dev
```

## Connecting

The first screen offers these ways in:

- **Sign in with browser** — enter the control plane's URL (`https`, or `http`
  to this machine only) and sign in through its identity provider.
- **Sign in with OpsAPI** — shown only when the control plane offers it
  (`wsl sign-in-methods`). Email and password go to OpsAPI through the CLI's
  stdin, never its arguments; if OpsAPI emails a code, the window asks for it.
  The control plane checks the session with OpsAPI and SCIM, and checks SCIM
  again on every Connect.
- **Import WireGuard config…** — pick the `.conf` your administrator issued.
  The app connects straight to that WireGuard server; no control plane is
  involved. Configs with `PostUp`/`PreUp`/`PostDown`/`PreDown` are refused,
  because `wg-quick` would run those commands as root. Files exported by the
  official WireGuard apps import unchanged; a Windows byte order mark and CRLF
  line endings are removed.

If the official WireGuard app has a tunnel connected at the same time, the
dashboard names it: two tunnels routing the same addresses is the usual reason
a connection carries no traffic.

Connect and Disconnect show the macOS administrator dialog: bringing an
interface up needs root, and the app itself never has it.

## DNS overrides

The dashboard lists overrides, adds and removes them, and turns them on and
off. Changing an existing name's address applies immediately; adding a new
name asks for administrator rights once, to route it. See
[docs/DNS.md](../../docs/DNS.md).

## Finding the CLI

A process launched from Finder inherits a minimal `PATH` with no Homebrew and
no `/usr/local/bin`, so the app searches, in order:

1. `WSL_CLI`
2. next to its own executable, then the bundle's `Resources` — a released app
   must not pick up a different version than it shipped with
3. `PATH`
4. `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`

When none of those has it, the window says so and offers a retry rather than
showing an empty dashboard.

## Privilege

Bringing a WireGuard interface up needs root, and a GUI has no terminal for
`sudo` to prompt on. Connect and disconnect therefore run `wsl … --gui`, which
asks macOS for the privilege through its own authorization dialog. Only
`wg-quick` is elevated. The app itself never runs as root.

## What it shows

The window is laid out like the WireGuard app's "Manage Tunnels": every
imported tunnel on the left, with a dot that is green only while its interface
is up; the selected one on the right — interface, status, public key,
addresses, DNS, MTU, and each peer with its endpoint, allowed IPs and
keepalive — with **Activate** / **Deactivate** and **Edit**.

- **+** imports one or more `.conf` files; **−** removes the selected tunnel
  (after asking; the tunnel that is up cannot be removed).
- One tunnel is up at a time. Activating another replaces it in a single
  administrator prompt.
- **Edit** opens the config text, private key included, and saves it through
  the same validation as an import. Renaming is done here too.
- **Organisation sign-in**, **DNS overrides** and **Device posture** are their
  own entries below the tunnel list.

Everything shown comes from `wsl status --json` (`profiles`, `profile`,
`interface`), so the window cannot disagree with `wsl profile list` and
`wsl status` in a terminal.

State refreshes every five seconds, and after every action.
