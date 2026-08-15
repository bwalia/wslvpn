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
| namespace (future) | tenant (not in MVP schema) |
