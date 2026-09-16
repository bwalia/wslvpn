# Desktop

The macOS app (`apps/wsl-desktop`) is a Tauri window over the CLI:

```text
wsl-desktop → wsl CLI → wsl-agent → control plane
                     ↘ wg-quick (elevated per command)
```

The GUI holds no state. Every field it shows comes from `wsl status --json`, and
every button runs a CLI command — so "connected" has one implementation and the
window cannot disagree with `wsl status` in a terminal.

The GUI never runs as root. Connect and disconnect pass `--gui`, which tells the
agent that there is no terminal for `sudo` to prompt on and it should ask macOS
for the privilege through Authorization Services instead. Only the `wg-quick`
invocation is elevated.

`src-tauri` is its own cargo workspace. Tauri links the platform webview —
WebKit on macOS, webkit2gtk on Linux — which the control plane has no reason to
depend on and the CI runner has no reason to install, so it is kept out of the
root lockfile and out of the supply-chain check that covers the shipped
services.

See [apps/wsl-desktop/README.md](../apps/wsl-desktop/README.md) for development
setup and how the app locates the CLI.
