# Operations

Running the control plane in production: what to deploy, what to watch, and what
to do when something is wrong.

- [Local stack](#local-stack)
- [Production deployment](#production-deployment)
- [Bootstrap checklist](#bootstrap-checklist)
- [Credentials and rotation](#credentials-and-rotation)
- [Health and monitoring](#health-and-monitoring)
- [Backup and restore](#backup-and-restore)
- [Audit log operations](#audit-log-operations)
- [Runbooks](#runbooks)

## Local stack

```bash
make dev     # Postgres, Dex, control plane, gateway
make test    # brings up a throwaway Postgres and runs the whole suite
make down
```

`make test` needs a database because the control-plane authorization tests drive
the real router against real SQL. Skipped authorization tests are
indistinguishable from absent ones, so they are not skippable.

## Production deployment

```bash
helm upgrade --install wslvpn oci://ghcr.io/bwalia/charts/wslvpn \
  --namespace wslvpn --create-namespace \
  --set config.publicUrl=https://vpn.example.com \
  --set ingress.host=vpn.example.com \
  --set config.oidc.issuer=https://idp.example.com \
  --set config.oidc.clientId=wslvpn \
  --set 'config.adminEmails[0]=security@example.com'
```

What the chart assumes, and what it does not do for you:

| Concern | Handled by the chart | Yours to provide |
| --- | --- | --- |
| Replicas, spread, disruption budget | Yes | — |
| Liveness / readiness | Yes | — |
| TLS | Ingress annotation and TLS block | The certificate |
| Secrets | Referenced by name | The `Secret` itself |
| PostgreSQL | No | A managed instance with its own backups |
| Gateways | No | Deployed on the network paths they serve |

**The control plane speaks plain HTTP.** Session bearer tokens travel on these
requests, so it must sit behind TLS termination and must never be reachable
directly from an untrusted network.

### High availability

The control plane holds no state of its own — everything is in PostgreSQL — so
replicas are interchangeable and scale horizontally. Two consequences worth
knowing:

- **Migrations are safe to run concurrently.** Every replica runs them at
  startup and sqlx serialises them behind a Postgres advisory lock, so a rollout
  where three pods start at once applies each migration once.
- **Rate limits are per replica.** The limiter keeps its counters in process, so
  the effective budget is the configured value times the replica count. Put a
  shared limiter at the ingress if you need a global one; the in-process limiter
  is the floor, not the ceiling.

A control-plane outage does **not** disconnect anyone. Traffic flows device →
gateway over WireGuard and never touches the control plane. What stops is
establishing *new* sessions, and revocations stop converging until it returns.

## Bootstrap checklist

1. Provision PostgreSQL. Enable automated backups and point-in-time recovery.
2. Create the `Secret` with all five keys. A missing key is a startup error.
3. Deploy the chart with `config.adminEmails` naming at least one person. **On a
   fresh database, an empty list means nobody can reach the administrative API**
   — there is no other way for the first administrator to come into existence.
4. Configure the OIDC client at the identity provider with the redirect URI
   `https://<host>/auth/oidc/callback`.
5. Apply networks and policies through GitOps.
6. Enroll gateways (below).
7. Sign in from the CLI or desktop client and connect.

## Credentials and rotation

Five credentials, with different lifetimes and blast radii. All are stored as
SHA-256 digests; none can be read back.

| Credential | Held by | Grants | Rotate by |
| --- | --- | --- | --- |
| `ops_service_token` | Provisioning systems | `/api/v1/ops` | Change the Secret, restart |
| `scim_service_token` | The identity provider | `/SCIM/v2` | Change the Secret, restart |
| `gateway_registration_token` | New gateways | First enrollment only | Change the Secret, restart |
| Per-gateway credential | One gateway | That gateway's config and heartbeat | `POST /api/v1/gateways/{id}/rotate-token` |
| User access token | One person | Their session, 8 hours | Expires on its own |

Rotating the ops or SCIM token invalidates the old value on the next start,
because bootstrap overwrites the stored digest.

Omitting `scim_service_token` entirely **deactivates** any SCIM credential a
previous configuration seeded, rather than leaving a live provisioning key that
nobody is tracking.

### Enrolling a gateway

A gateway presents `gateway_registration_token` once, and receives its own
credential in return. It persists that at `<state_dir>/enrollment.json` with
mode 0600 and uses it from then on.

Re-enrolling a name that already exists **also** requires the current
credential. Without that rule, anyone holding the shared enrollment secret could
repoint a live gateway's endpoint and draw its traffic to a host of their
choosing. A gateway that has lost its credential needs an administrator:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://vpn.example.com/api/v1/gateways/$GATEWAY_ID/rotate-token
```

Then place the returned `auth_token` in the gateway's `enrollment.json`, or
delete the gateway record and let it enroll fresh.

## Health and monitoring

| Endpoint | Meaning | Use for |
| --- | --- | --- |
| `/livez` | The process is up. Does not touch the database. | Liveness probe |
| `/readyz` | This replica can reach PostgreSQL. | Readiness probe, load balancer |
| `/health` | Status and version. | Humans |
| `/metrics` | Prometheus exposition. | Scraping |

Liveness deliberately ignores the database. A liveness probe that fails during a
database outage has the orchestrator restart every replica, which fixes nothing
and turns a degradation into an outage.

### Alerts worth having

| Signal | Why it matters |
| --- | --- |
| `wsl_audit_verification_failures > 0` | The audit chain no longer verifies. Treat as an incident. |
| `wsl_rate_limited_total` rising sharply | Credential guessing, or a client in a retry loop. |
| `wsl_policy_denials` rising sharply | A policy change locked people out, or someone is probing. |
| No gateway heartbeat for 3 intervals | The gateway is applying a stale configuration; revocations are not converging. |
| `readyz` failing on any replica | That replica cannot reach PostgreSQL. |

## Backup and restore

Everything durable is in PostgreSQL: identities, policies, sessions, IPAM
allocations, gateway records and the audit log. Nothing on a control-plane pod
needs backing up.

### What to back up

```bash
# Nightly full dump, plus continuous WAL archiving for point-in-time recovery.
pg_dump --format=custom --no-owner --no-privileges \
  --file="wslvpn-$(date -u +%Y%m%dT%H%M%SZ).dump" "$DATABASE_URL"
```

Encrypt at rest and store outside the account that runs the database, so the
same compromise cannot take both.

**Retain the audit log separately.** A backup that can be restored can also be
restored selectively, so a database backup is not by itself proof of what
happened. Ship audit events to a log store that the database's owner cannot
write to.

### Restore

```bash
createdb wslvpn_restored
pg_restore --no-owner --no-privileges --dbname=wslvpn_restored wslvpn-*.dump
```

Then, before pointing the control plane at it:

1. **Verify the audit chain.** `SELECT * FROM audit_verify();` — an empty result
   means the log is intact. A restore that silently drops or reorders audit rows
   will show up here.
2. **Expect every live session to be stale.** Sessions restored from a backup
   reference peers that gateways no longer have. They expire on their own, but
   revoking them explicitly is faster than waiting.
3. **Re-enroll gateways** if the backup predates their current credentials.
   Their stored `enrollment.json` will fail against restored digests, and each
   gateway will re-enroll on its own if the shared enrollment secret still
   matches.

### Recovery objectives

| Failure | Effect on users | Recovery |
| --- | --- | --- |
| One control-plane replica | None | Kubernetes reschedules |
| All control-plane replicas | Existing sessions keep working; no new ones | Restore the deployment |
| PostgreSQL failover | Brief inability to create sessions | Managed failover |
| PostgreSQL loss, restored from backup | Sessions created since the backup are lost | Restore, then re-enroll gateways |

## Audit log operations

The log is append-only and chained: each entry carries the hash of the one
before it, so altering or removing an entry invalidates every hash after it.

```bash
# Is the log intact?
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://vpn.example.com/api/v1/audit/verify
```

`UPDATE` and `DELETE` are refused by trigger. A correction is a **new event
describing the correction**, never an overwrite.

### Retention

Because deletion is blocked, trimming the log is a deliberate act with a
deliberate procedure. It breaks the chain at the trim point by design; what
matters is that the break is recorded rather than discovered later.

```sql
-- 1. See what you have.
SELECT * FROM audit_retention;

-- 2. Export everything you are about to remove, to immutable storage.
\copy (SELECT * FROM audit_events WHERE created_at < now() - interval '2 years')
      TO 'audit-archive.csv' CSV HEADER

-- 3. Trim, with the guard triggers disabled for exactly this transaction.
BEGIN;
ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_delete;
DELETE FROM audit_events WHERE created_at < now() - interval '2 years';
ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_delete;
COMMIT;

-- 4. Record that it happened, so the gap has an explanation in the log itself.
INSERT INTO audit_events (action, actor_type, actor_id, details)
VALUES ('audit.trimmed', 'system', 'retention-policy',
        '{"before": "2 years", "archive": "audit-archive.csv"}');
```

After a trim, `audit_verify()` reports a sequence gap at the trim point. That is
expected and is the reason step 4 is not optional.

## Runbooks

### The audit chain stopped verifying

1. `GET /api/v1/audit/verify` gives the sequence number of the first break.
2. Read the entries around it: `SELECT * FROM audit_events WHERE seq BETWEEN
   $break - 5 AND $break + 5 ORDER BY seq;`
3. A `problem` of *gap in sequence* means an entry was deleted; *contents do not
   match* means one was edited; *link does not match* means one was inserted or
   reordered.
4. Unless a documented retention trim explains it, treat this as a compromise of
   database credentials. The application cannot produce this state: `UPDATE` and
   `DELETE` are refused by trigger, so whoever did this had direct database
   access and disabled them.
5. Rotate the database credentials, compare against your external log store, and
   preserve the current state before further writes.

### A user has left the company

Deactivating reaches the data plane, not just the directory:

```bash
curl -X POST -H "Authorization: Bearer $OPS_TOKEN" \
  https://vpn.example.com/api/v1/ops/users/$USER_ID/disable
```

This revokes their sessions, removes their WireGuard peers, and bumps the
affected gateways' config versions. Their access tokens stop working
immediately — the bearer extractor joins against `users.active` — and their
tunnel drops on the next gateway heartbeat, within `heartbeat_secs`.

Through SCIM, setting `active: false` from the identity provider does the same.

### A gateway credential may have leaked

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://vpn.example.com/api/v1/gateways/$GATEWAY_ID/rotate-token
```

The old credential stops working the moment this returns. The gateway will get
401 on its next heartbeat, discard its stored copy, and re-enroll — provided it
still holds the shared enrollment secret. Otherwise place the returned token in
its `enrollment.json` directly.

### The shared enrollment secret may have leaked

A holder can enroll *new* gateway names but cannot take over existing ones —
re-enrollment requires the target's current credential. Still:

1. Change `gateway_registration_token` in the Secret and restart the control
   plane.
2. `SELECT name, endpoint, created_at FROM gateways ORDER BY created_at DESC;`
   and delete any gateway you do not recognise.
3. `SELECT * FROM audit_events WHERE action = 'gateway.enrolled' ORDER BY seq
   DESC;` shows every enrollment, with endpoints.

### Nobody can reach the administrative API

The role is reconciled from configuration on every start, so this is a config
fix rather than a database fix:

```bash
helm upgrade wslvpn ... --set 'config.adminEmails[0]=you@example.com'
```

If the control plane will not start at all, grant the role directly and restart:

```sql
UPDATE users SET role = 'admin' WHERE email = 'you@example.com';
```

Then add the address to `config.adminEmails`, or the next start will demote it
again.

### Suspected credential guessing

`wsl_rate_limited_total` rising means the limiter is refusing requests. The
budget is per replica; tighten `config.rateLimit.auth` and, for a global budget,
add a limiter at the ingress. Failed authentication attempts appear in the
control plane's structured logs as `denied:` warnings with the path and, for
gateway credentials, the gateway id.
