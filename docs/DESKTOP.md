# Desktop

The macOS app (`apps/wsl-desktop`) is a Tauri window over the CLI:

```text
wsl-desktop → wsl CLI → wsl-agent → control plane
                     ↘ wg-quick (elevated per command)
```

The GUI holds no state. Every field it shows comes from `wsl status --json`, and
every button runs a CLI command — so "connected" has one implementation and the
window cannot disagree with `wsl status` in a terminal.

There are two ways in. **Sign in** to a control plane (its URL is entered on
the first screen), or **Import WireGuard config** to connect straight to an
existing WireGuard server with the `.conf` its administrator issued — no
control plane needed. Either way, Connect and Disconnect do the same thing:
see [CLIENT.md](CLIENT.md#connecting-with-a-wireguard-config). The dashboard
also manages [DNS overrides](DNS.md).

The GUI never runs as root. Connect and disconnect pass `--gui`, which tells the
agent that there is no terminal for `sudo` to prompt on and it should ask macOS
for the privilege through Authorization Services instead. Only the `wg-quick`
invocation (and, for DNS overrides, writing `/etc/resolver`) is elevated.

The released app bundles the `wsl` CLI at `Contents/MacOS/wsl` and uses that
copy first, so it never runs a different version from whatever is on `PATH`.
`make app` in `apps/wsl-desktop` builds both.

`src-tauri` is its own cargo workspace. Tauri links the platform webview —
WebKit on macOS, webkit2gtk on Linux — which the control plane has no reason to
depend on and the CI runner has no reason to install, so it is kept out of the
root lockfile and out of the supply-chain check that covers the shipped
services.

See [apps/wsl-desktop/README.md](../apps/wsl-desktop/README.md) for development
setup and how the app locates the CLI.
