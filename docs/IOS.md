# iOS

A WireGuard client for iPhone and iPad: a SwiftUI app, a packet tunnel
extension running the real wireguard-go, and the same control-plane API the CLI
uses.

```text
WSLVPN (app)  ──▶ control plane          sign in, register, create session
      │
      └──▶ WSLTunnel (NEPacketTunnelProvider) ──▶ WireGuardKit ──▶ wireguard-go
```

The app makes every decision that needs a user — signing in, choosing a network,
creating a session — and the extension does one thing: bring an interface up
from a configuration the app left for it. The extension has no UI, may be
started by the system while the screen is locked, and is killed without
ceremony if it uses too much memory, so it is kept as small as it can be.

See [apps/wsl-ios/README.md](../apps/wsl-ios/README.md) for building it.

## Deployment prerequisites

**The control plane must allow the app's callback scheme.** A phone cannot
listen on loopback the way the desktop client does, so it registers a
private-use URI scheme and is sent back through that — RFC 8252 section 7.1.
Nothing is accepted unless it is named:

```yaml
identity:
  oidc:
    native_schemes:
      - io.wsl.zerotrust
```

An empty list — the default — means no mobile client can complete a login,
which is the right default for a deployment that does not have one. Private-use
schemes are first come, first served: a second app can register the same one.
PKCE makes an intercepted code worthless without the verifier, and the allowlist
means an operator still decides which apps may collect a login at all.

Schemes must be derived from a domain name you control. `io.wsl.zerotrust` is
accepted; `wslvpn` is refused, because a bare word is squattable in a way a
reverse-domain name is not. The validator runs at startup, so a scheme nobody
can safely accept stops the deployment rather than failing one login at a time.

**Apple must grant the Network Extension entitlement.**
`com.apple.developer.networking.networkextension` with `packet-tunnel-provider`
is issued per App ID through the developer portal on a paid account. Without it
the extension will not load on a device, and there is no way to work around that
or to test it on a simulator.

## Device posture on iOS

The signal names match the agent's, because a policy naming `disk_encryption`
has to mean the same thing whichever client answers it. What iOS lets an app
observe is narrower than macOS, and the difference is reported rather than
papered over.

| Signal | iOS | Note |
| --- | --- | --- |
| `disk_encryption` | pass / fail | Whether a device passcode is set |
| `device_management` | pass / unknown | Managed app configuration present |
| `firewall` | unsupported | There is no host firewall on iOS |
| `os_version`, `agent_version` | pass | Informational |

**`disk_encryption` is really "is there a passcode".** iOS encrypts the file
system unconditionally, so asking whether the disk is encrypted always answers
yes and tells you nothing. What decides whether data is protected at rest is the
passcode: without one, the Data Protection class keys are available whenever the
device is powered on. An administrator reading an audit log should not read this
signal as FileVault, and the detail string says so.

**`device_management` is `unknown` when absent, never `fail`.** There is no
public API that reports MDM enrolment. The closest an app can get is a managed
app configuration, which an MDM server can push. Its presence proves enrolment;
its absence proves nothing, because an enrolled device whose administrator never
pushed a configuration is indistinguishable from an unenrolled one. Since
`compliant: true` denies on `unknown`, a fleet of iOS devices will fail a blanket
compliance check until the MDM pushes something. Either push a configuration, or
name the signals that matter:

```yaml
spec:
  device:
    requiredSignals:
      - disk_encryption
```

See [Posture](POSTURE.md) for how the results are evaluated, and for the limit
that applies to all of this: every signal is the endpoint's own account of
itself.

## What has not been proven

The app compiles, the extension links wireguard-go, and everything testable off
a device is tested — 40 tests covering the wire format, PKCE against the RFC
vector, key handling, posture and validation.

Nobody has watched it carry a packet. Network Extensions do not load in the
Simulator, so the tunnel can only be exercised on a physical device with the
entitlement granted and a gateway to reach. That is the next thing to do, and
until it is done this is a client that builds rather than a client that works.
