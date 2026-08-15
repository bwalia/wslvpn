# API

Versioned REST API under `/api/v1/`.

Interactive docs: `/swagger-ui` (OpenAPI at `/api-docs/openapi.json`).

## Auth

| Client | Mechanism |
|--------|-----------|
| User / agent / CLI | Bearer access token from OIDC or `/auth/dev/login` (localhost only) |
| OpsAPI | Bearer service token (`bootstrap.ops_service_token`) on `/api/v1/ops/*` |
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

See also [OPSAPI.md](OPSAPI.md), [SCIM.md](SCIM.md), [OIDC.md](OIDC.md).
