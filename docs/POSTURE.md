# Device posture

The agent reports what it can measure about the endpoint. The control plane
feeds that into policy evaluation, where `device.compliant` and
`device.requiredSignals` decide whether it is enough.

## What posture is not

Every signal here is the endpoint's own account of itself, collected by an agent
running as the user. An endpoint that has been taken over will report whatever
its owner wants, and nothing in this document changes that.

Posture raises the cost of using a compromised or careless device. It is not an
authentication control and it is not attestation. Treat it as one input among
identity, group membership and network policy — never as the thing standing
between an attacker and the network.

## Signals

| Signal | macOS | Linux |
| --- | --- | --- |
| `os_version` | `sw_vers` | `PRETTY_NAME` from `/etc/os-release` |
| `agent_version` | build version | build version |
| `disk_encryption` | `fdesetup status` | a dm-crypt mapping under `/sys/class/block` |
| `device_management` | `profiles status -type enrollment` | unsupported |
| `firewall` | `socketfilterfw --getglobalstate` | unsupported |

None of these needs root. A posture check that prompts for a password is a
posture check that gets skipped.

`disk_encryption` treats a conversion in progress as a failure. `fdesetup` starts
reporting "FileVault is On." the moment encryption begins, and a disk 41% of the
way through its first pass is not protected; decryption in progress is protection
being removed.

Linux has no single enrolment mechanism or firewall to interrogate, so those
report `Unsupported` rather than being guessed at from whatever happens to be
installed.

## The four results

| Result | Meaning |
| --- | --- |
| `Pass` | The check ran and the device is in the required state |
| `Fail` | The check ran and it is not |
| `Unknown` | The check could not run |
| `Unsupported` | The platform has no such concept |

`Unknown` is not a pass. An agent that cannot read FileVault's state has told us
nothing, and treating silence as compliance is how a requirement becomes
decorative.

`Unsupported` passes the blanket check, because denying a platform that has no
such concept would make a policy unsatisfiable rather than express anything
about the device. It does not satisfy a signal asked for by name.

## Requiring signals in a policy

`device.compliant: true` — the default — requires every signal to be `Pass` or
`Unsupported`, and requires there to be signals at all:

```yaml
spec:
  device:
    compliant: true
```

That is usually stricter than intended. On a default macOS install the
application firewall is off, so a fleet will fail this on day one. Name the
checks that matter instead:

```yaml
spec:
  device:
    requiredSignals:
      - disk_encryption
```

Naming any signal replaces the blanket check: an operator who says which checks
matter has said the others do not. Each named signal must be present and
`Pass` — absence, `Unknown` and `Unsupported` all fail.

`device.managed: true` is answered by the `device_management` signal being
`Pass`. It is the device's claim about its own enrolment, not a record the
administrator keeps; an admin-held record would be stronger and is the direction
to take this next.

## Seeing what a device reports

```bash
wsl status
```

```text
Posture:    Failing: disk_encryption, firewall
  os_version         ok    macOS 26.5.1 (25F80)
  agent_version      ok    0.1.0
  disk_encryption    FAIL  FileVault is Off.
  device_management  ok    MDM: Yes (User Approved); DEP: Yes
  firewall           FAIL  Firewall is disabled. (State = 0)
```

`wsl status --json` emits the same signals with their raw details, and the
desktop app renders them. The summary names the failing checks rather than
counting them — a user reading "Failing" and nothing else knows they are blocked
and nothing about what to do next.
