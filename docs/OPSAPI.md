# OpsAPI integration

OpsAPI remains the identity source of truth. It calls WSL; WSL does not drive OpsAPI CRUD in MVP.

## Direction

```text
OpsAPI  --service token-->  WSL /api/v1/ops/*
```

## Endpoints

All require `Authorization: Bearer <ops_service_token>`.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/ops/users` | Create user |
| POST | `/api/v1/ops/users/{id}/disable` | Disable + revoke sessions |
| POST | `/api/v1/ops/users/{id}/enable` | Re-enable |
| DELETE | `/api/v1/ops/users/{id}` | Delete |
| POST | `/api/v1/ops/groups` | Create group |
| POST | `/api/v1/ops/groups/{id}/members/{user_id}` | Assign group |
| DELETE | `/api/v1/ops/groups/{id}/members/{user_id}` | Remove group |
| POST | `/api/v1/ops/devices/{id}/revoke` | Revoke device |
| GET | `/api/v1/ops/sessions` | Query sessions |
| GET | `/api/v1/ops/audit` | Query audit |

Local default token: `dev-ops-token-change-me` (compose / example config).

## Mapping

| OpsAPI | WSL |
|--------|-----|
| `users.uuid` / email | `users.id` / `email` |
| groups | access policy subjects |
| namespace | tenant (1:1, planned — see [ADR-0002](decisions/0002-multi-tenancy-config-first.md)) |

## What OpsAPI actually provides

Verified by reading `lapis/app.lua`, `lapis/routes/` and `lapis/helper/` and by
exercising a running instance. Recorded because the shipped
`lapis/api-docs/swagger.json` documents four paths out of well over a hundred —
it is generated from the database schema and is not a usable contract.

| Capability | Reality |
|---|---|
| Tenancy | Namespaces: `namespace_members`, `namespace_roles`, invitations, ownership transfer, and a switch that reissues the token |
| Interactive login | `POST /auth/login` → **mandatory email-OTP 2FA**, returning `requires_2fa` and a session token, never a JWT. `POST /auth/2fa/verify` completes it |
| Machine credentials | API keys prefixed `opsk_`, bound to one namespace, carrying scopes; refused with another namespace's header |
| Token format | `HS256`, shared `JWT_SECRET_KEY`. Claims nested under `userinfo`; `iss` is the string `"opsapi"`; no `aud` |
| OIDC provider surface | None — no discovery, no JWKS, no `/authorize` |
| SCIM | `/scim/v2/Users` and `/scim/v2/Groups` (lowercase path) |
| Directory | `/api/v2/users`, `/api/v2/groups`, `/api/v2/roles`, `/api/v2/permissions` |
| Request encoding | `/auth/login` reads **form-encoded** parameters; a JSON body is silently ignored |
| Error envelope | `{error: {code, category, context, correlation_id, occurrence_uuid, message, title}}` |

Because tokens are symmetric, anything able to validate an OpsAPI token can also
mint one. WSLVPN therefore does not hold `JWT_SECRET_KEY` and does not validate
OpsAPI JWTs — see
[ADR-0003](decisions/0003-opsapi-is-a-directory-not-a-provider.md).

## Planned direction

Today OpsAPI calls WSL. The outbound direction — WSL reading users and groups
from OpsAPI over SCIM, authenticated with an `opsk_` API key — is Phase 2 of the
[implementation plan](IMPLEMENTATION-PLAN.md) and is not built yet.
