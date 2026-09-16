# WSL Zero Trust — Desktop (macOS)

A window over the `wsl` command-line tool. The GUI holds no state and performs
no privileged operation of its own: everything it shows is read back from
`wsl status --json`, and everything it does is a CLI invocation. There is one
implementation of what "connected" means, and the window cannot drift from it.

## Dev

```bash
cd apps/wsl-desktop
npm install
npm run tauri dev
```

Requires a Rust toolchain, and macOS for native builds. `src-tauri` is its own
cargo workspace — Tauri pulls in the platform webview, which the control plane
has no reason to link against and CI has no reason to install — so it builds
from that directory rather than with the rest of the repo.

Point the app at a development build of the CLI with `WSL_CLI`:

```bash
cargo build -p wsl-cli
WSL_CLI=$PWD/../../target/debug/wsl npm run tauri dev
```

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

| Field | Source |
| --- | --- |
| Signed in as, Device, Identity, Posture | `wsl status --json` |
| Interface | the `utun` the OS reports, or "Down" |
| Networks | one row per network, with the agent's own state string |
| Gateway, Session expires | shown only when there is a session |

A session record and a live interface are separate things, so the UI keeps them
separate: `Session open, tunnel down` is a state a user needs to see, not a
rounding error. The status dot pulses only when an interface is actually up.

State refreshes every five seconds, and after every action.
