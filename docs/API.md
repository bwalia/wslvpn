# API

Versioned REST API under `/api/v1/`.

Interactive docs: `/swagger-ui` (OpenAPI at `/api-docs/openapi.json`).

## Auth

| Client | Mechanism |
|--------|-----------|
| User / agent / CLI | Bearer access token from OIDC or `/auth/dev/login` (localhost only) |
| OpsAPI | Bearer service token (`bootstrap.ops_service_token`) on `/api/v1/ops/*` |
| Edge proxy | Bearer service token on `/api/v1/sessions/by-ip/{ip}` |
| Gateway | Registration token on register; subsequent calls by gateway id |

## Core resources

- `GET/POST /api/v1/users`
- `GET/POST /api/v1/groups`
- `POST /api/v1/devices/register`
- `POST /api/v1/devices/{id}/revoke`
- `GET/POST /api/v1/networks`
- `GET /api/v1/policies` · `POST /api/v1/policies/apply`
- `GET/POST /api/v1/sessions` · `DELETE /api/v1/sessions/{id}`
- `POST /api/v1/gateways/register` · `POST /api/v1/gateways/{id}/heartbeat`
- `GET /api/v1/audit`

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
