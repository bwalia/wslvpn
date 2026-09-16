# API

Versioned REST API under `/api/v1/`.

Interactive docs: `/swagger-ui` (OpenAPI at `/api-docs/openapi.json`), mounted
only when `server.expose_docs` is true. It is off by default — the document
enumerates every route and schema on the control plane.

## Auth

Every route under `/api/v1` and `/SCIM/v2` requires a credential. See
[AUTHORIZATION.md](AUTHORIZATION.md) for the rules and the reasoning.

| Client | Mechanism | Reaches |
|--------|-----------|---------|
| User / agent / CLI | Bearer access token from OIDC, or `/auth/dev/login` when explicitly enabled on a loopback deployment | Their own resources |
| Administrator | The same, with `role = 'admin'` | Everything |
| OpsAPI | Service token, scope `ops:provision` | `/api/v1/ops/*` |
| Identity provider | Service token, scope `scim:manage` | `/SCIM/v2/*` |
| Edge proxy | Service token, scope `ops:provision` | `/api/v1/sessions/by-ip/{ip}` |
| Gateway | Shared secret to enroll; its own credential thereafter | That gateway's config and heartbeat |

A member reading another user's resource gets `404`, not `403`: confirming that
an id exists is itself a disclosure.

## Core resources

- `GET/POST /api/v1/users`
- `GET/POST /api/v1/groups`
- `POST /api/v1/devices/register`
- `POST /api/v1/devices/{id}/revoke`
- `GET/POST /api/v1/networks`
- `GET /api/v1/policies` · `POST /api/v1/policies/apply`
- `GET/POST /api/v1/sessions` · `DELETE /api/v1/sessions/{id}`
- `POST /api/v1/gateways/register` · `POST /api/v1/gateways/{id}/heartbeat`
- `POST /api/v1/gateways/{id}/rotate-token` (admin)
- `GET /api/v1/audit` · `GET /api/v1/audit/verify` (admin)

## Gateway enrollment

```
POST /api/v1/gateways/register
{ "name": "edge-1", "public_key": "…", "endpoint": "1.2.3.4:51820",
  "network_id": "…", "token": "<shared enrollment secret>" }
```

```json
{ "id": "…", "name": "edge-1", "…": "…", "auth_token": "<disclosed once>" }
```

`auth_token` is the gateway's own credential and is never readable again. It is
presented as `Authorization: Bearer` on config and heartbeat, and the
configuration served is for the id that credential resolves to — a valid
credential cannot read another gateway's peers.

Re-registering a name that already exists requires that gateway's current
credential in the `Authorization` header, so the shared enrollment secret alone
cannot repoint a live gateway's endpoint. Lost credentials are recovered with
`POST /api/v1/gateways/{id}/rotate-token` as an administrator.

## Audit

`GET /api/v1/audit` returns events newest first, each carrying `actor_type` and
`actor_id` — who caused it — alongside `user_id`, which is who it was about.

`GET /api/v1/audit/verify` walks the hash chain:

```json
{ "intact": true }
```

or, when an entry has been altered or removed:

```json
{ "intact": false,
  "first_break": { "seq": 42, "id": "…", "problem": "contents do not match the recorded hash" } }
```

## Session identity

```
GET /api/v1/sessions/by-ip/{ip}
Authorization: Bearer <service token>
```

Resolves an overlay address to the identity behind it, so an edge proxy can
enforce per-user access on VPN-only endpoints rather than merely per-network.

```json
{
  "session_id": "…",
  "user_id": "…",
  "email": "alice@example.com",
  "device_id": "…",
  "groups": ["staff", "platform-admins"],
  "assigned_ip": "10.8.1.7/32",
  "expires_at": "2026-08-15T18:00:00Z"
}
```

Only active, unexpired sessions belonging to active users resolve. Revoked,
expired and never-allocated addresses are all `404`, so the endpoint cannot be
used to probe which addresses exist. The address is matched exactly against the
allocation, so a client cannot assume a neighbour's identity.

Callers should cache by address on a short TTL — that TTL is the revocation lag.
See wslproxy's `docs/VPN_ACCESS.md` for the consuming side.

See also [OPSAPI.md](OPSAPI.md), [SCIM.md](SCIM.md), [OIDC.md](OIDC.md).
