# Upgrading

## To the release that makes device posture real

Posture used to be four hardcoded values. `disk_encryption` was always
`Unknown`, `device_management` was always `Unsupported`, and nothing was
measured — so no device could fail a compliance check. The control plane also
passed `device_managed: true` for every session, so `device.managed` in a policy
was satisfied by every device that asked.

Both requirements now mean something, and **devices that were being allowed will
start being denied.** That is the point of the change, but it will not feel like
it at three in the morning, so read this first.

### What changed

| Change | Effect |
| --- | --- |
| Posture is measured | `disk_encryption`, `device_management` and `firewall` can now report `Fail` |
| `Unknown` no longer passes | A check that could not run is not a check that passed |
| Empty posture no longer passes | `all()` over no signals was vacuously true; an agent sending nothing satisfied everything |
| `device.managed` reads the reported signal | Was hardcoded `true` |
| `device.requiredSignals` added | Name the checks that matter instead of requiring all of them |

`Unsupported` still passes the blanket `compliant: true` check: denying a
platform that has no such concept would make a policy unsatisfiable rather than
express anything. It does **not** satisfy a signal named in `requiredSignals`,
or `managed: true` — an operator asking a specific question has not been
answered by "this platform cannot tell you".

### Before you upgrade

`device.compliant` defaults to `true`, so a policy with no `device:` block is
affected. Find out what your fleet actually reports before the new rule starts
denying on it:

```bash
wsl status          # per device, lists every signal and its detail
```

A Mac with FileVault off, no MDM enrolment, or the application firewall
disabled will now fail `compliant: true`. On a default macOS install the
firewall is off, so expect that one.

### Narrowing the requirement

Requiring every check to pass is rarely what an operator means. Name the ones
that matter:

```yaml
spec:
  device:
    requiredSignals:
      - disk_encryption
```

Naming any signal replaces the blanket check, so the firewall and enrolment
states above stop mattering while full-disk encryption is still enforced.

To roll back to the old effective behaviour while you work through a fleet, set
`compliant: false` on the affected policies. That is a real reduction in
control, not a no-op — it was only ever equivalent because nothing was measured.

### A limit worth knowing

Every signal is the endpoint's own account of itself, collected by an agent
running as the user. A device that has been taken over will report whatever its
owner wants. Posture raises the cost of using a compromised or careless machine;
it does not authenticate one. `device.managed` in particular is the device's
claim, not a record the administrator keeps — an admin-held enrolment record
would be stronger and is the direction to take this next.

## To the release that adds authorization

This release closes an authorization gap and, in doing so, changes behaviour
that existing deployments and integrations rely on. **Read this before
upgrading a running deployment.**

### What changed, and what breaks

Before this release, every route under `/api/v1` and all of `/SCIM/v2` answered
an anonymous caller. Anything that was working *because* of that will stop.

| Change | What breaks | What to do |
| --- | --- | --- |
| `/api/v1` requires a credential | Scripts calling the API without one | Use an admin session token, or move to `/api/v1/ops` with a service token |
| `/SCIM/v2` requires `scim:manage` | The identity provider's SCIM connector | Set `bootstrap.scim_service_token` and configure the IdP with it |
| Administrative routes require `role = 'admin'` | Ordinary users calling them | Add the addresses to `bootstrap.admin_emails` |
| Gateways authenticate per gateway | Gateways on the old binary | Upgrade gateways; each re-enrolls automatically |
| `POST /gitops/apply` ignores `path` | Callers passing a path | Set `gitops.path` in configuration |
| `dev_login` needs an explicit flag | Local setups relying on the implicit rule | Set `identity.dev_login_enabled: true` |
| Swagger is opt-in | Bookmarks to `/swagger-ui` | Set `server.expose_docs: true` where you want it |
| `RegisterGatewayResponse` adds `auth_token` | Custom gateway implementations | Store the token and send it as `Authorization: Bearer` |

### Order of operations

1. **Add the new configuration first**, on the version you are already running.
   The fields are ignored by the old build, so this is safe and means the new
   one starts correctly on its first attempt:

   ```yaml
   identity:
     dev_login_enabled: false
   server:
     expose_docs: false
   bootstrap:
     scim_service_token: "${WSL_SCIM_SERVICE_TOKEN}"
     admin_emails:
       - "security@example.com"
   ```

   **`admin_emails` is not optional.** On a deployment with no administrator,
   the administrative API is unreachable and the only recovery is a manual
   `UPDATE users SET role = 'admin'`.

2. **Upgrade the control plane.** Migrations 003 and 004 run at startup and are
   serialised by an advisory lock, so a multi-replica rollout is safe.

   Migration 004 backfills hash-chain values across the whole audit table. On a
   large log this is the slow part of the upgrade; the startup probe allows 150
   seconds by default.

3. **Upgrade the gateways.** Each one enrolls, receives its own credential, and
   persists it. A gateway on the old binary heartbeats without a credential and
   gets 401 — it does not damage anything, but it stops receiving configuration
   until upgraded.

4. **Repoint SCIM.** The identity provider must send the new
   `scim_service_token`. Until it does, provisioning returns 401.

5. **Verify:**

   ```bash
   # No route should serve an anonymous caller.
   curl -s -o /dev/null -w '%{http_code}\n' https://vpn.example.com/api/v1/users   # 401

   # An administrator should reach it.
   curl -s -o /dev/null -w '%{http_code}\n' \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://vpn.example.com/api/v1/users                                          # 200

   # The audit chain should verify, including the backfilled history.
   curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://vpn.example.com/api/v1/audit/verify                                   # {"intact":true}

   # Gateways should be heartbeating.
   curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
     https://vpn.example.com/api/v1/gateways | jq '.[] | {name, last_heartbeat_at}'
   ```

### Rolling back

Migrations 003 and 004 are additive — new columns, triggers and functions — so
the previous build runs against the upgraded schema. Two caveats:

- The append-only triggers stay in place, so anything the old build did that
  updated or deleted an audit row would now fail. Nothing in the old build does.
- Gateways that have re-enrolled hold credentials the old build ignores. They
  keep working, because the old build does not check them.

Rolling *forward* again needs no special handling.

### If the upgrade goes wrong

**Nobody can administer the deployment.** Add an address to
`bootstrap.admin_emails` and restart. If the process will not start, set the
role directly and then fix the configuration, or the next restart demotes it
again:

```sql
UPDATE users SET role = 'admin' WHERE email = 'you@example.com';
```

**A gateway will not come back.** Rotate its credential as an administrator and
place the returned token in the gateway's `<state_dir>/enrollment.json`, or
delete the gateway record and let it enroll fresh.

**The process refuses to start.** The most likely causes are a `${VAR}` with no
value, an example secret on a non-loopback deployment, `dev_login_enabled` set
on a public host, or an empty `admin_emails`. Each names itself in the startup
error.
