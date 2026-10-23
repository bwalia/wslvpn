# Installing the client

One app on each platform, with three ways in:

| | Needs | Checked before connecting |
|---|---|---|
| **Import WireGuard config** | a `.conf` from your WireGuard server's administrator | nothing — the file is the credential |
| **Sign in with browser** | the control plane's URL | your identity provider, then policy and posture on every connect |
| **Sign in with OpsAPI** | the control plane's URL, when it offers it | OpsAPI `/auth/me` + SCIM at sign-in, SCIM again on every connect ([OPSAPI.md](OPSAPI.md#signing-in-with-an-opsapi-account)) |

Downloads are on the GitHub release for each version: the app installer for
your platform, the stand-alone CLI, and `SHA256SUMS`.

## macOS (12 or later)

```bash
brew install wireguard-tools bash
```

Open `WSL Zero Trust_<version>_aarch64.dmg` (Apple silicon) or `_x64.dmg`
(Intel) and drag the app to Applications. Connect asks for an administrator
password through the system dialog each time; the app itself never runs as
root.

The release is not yet signed with an Apple Developer ID. Until it is, open it
the first time with right-click → **Open**.

## Linux (x86_64)

```bash
sudo apt install wireguard-tools policykit-1    # Debian / Ubuntu
sudo dnf install wireguard-tools polkit          # Fedora
```

Install `wsl-zero-trust_<version>_amd64.deb`, or run the `.AppImage`. Connect
asks for privilege through polkit (`pkexec`). From a terminal, `wsl connect`
uses `sudo`.

DNS overrides are not available on Linux yet; the window says so.

## Windows 10 / 11 (x64)

Install **WireGuard for Windows** first — it provides the signed tunnel driver
and service the app drives:

```powershell
winget install WireGuard.WireGuard
```

Then run the `.msi` or the `-setup.exe`. Connect shows a UAC prompt and brings
the tunnel up as the `WireGuardTunnel$wsl` service, exactly as WireGuard's own
app would; it is listed in the WireGuard app while it is up. Disconnect removes
it.

The stand-alone CLI is published as `wslvpn.exe`, because `wsl.exe` on Windows
is Microsoft's Windows Subsystem for Linux. The desktop app only ever runs the
copy it ships with.

DNS overrides are not available on Windows yet; the window says so.

## Using an existing WireGuard server

Ask the server's administrator for a client `.conf` — the same file the
official WireGuard apps import — and choose **Import WireGuard config…**.
Files exported by the official apps, wg-easy or PiVPN import unchanged,
including Windows ones with a byte order mark. `PreUp`/`PostUp`/`PreDown`/
`PostDown` are refused, as they are by the official macOS and iOS apps, because
they would run as administrator.

If the official WireGuard app has a tunnel connected at the same time, the app
names it: two tunnels routing the same addresses is the usual reason a
connection carries no traffic.

## Building from source

See [apps/wsl-desktop/README.md](../apps/wsl-desktop/README.md). CI builds
every platform on each pull request (`.github/workflows/clients.yml`).
