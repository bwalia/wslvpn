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

## Signing in with an OpsAPI account

People can sign in to the VPN with their OpsAPI email and password (and the
emailed code, where the workspace requires one). The control plane never
verifies an OpsAPI token itself — it asks OpsAPI, from two directions — and asks
SCIM again before every connection. The reasoning is in
[ADR-0004](decisions/0004-sign-in-with-opsapi-by-asking-opsapi.md).

```text
app ──email, password──▶ OpsAPI /auth/login            → token, or "code sent"
app ──challenge, code──▶ OpsAPI /auth/2fa/verify       → token
app ──OpsAPI token────▶ WSL /auth/opsapi/exchange
                         WSL ──token──▶ OpsAPI /auth/me              (whose session? member of the workspace?)
                         WSL ──opsk_ key──▶ OpsAPI /scim/v2/Users/{uuid}   (active in the directory?)
                         → WSL access token
app ──connect──▶ WSL /api/v1/sessions
                         WSL ──opsk_ key──▶ OpsAPI /scim/v2/Users/{uuid}   (still active?)
```

Configure it on the control plane:

```yaml
identity:
  admission:
    provisioning: directory        # only people OpsAPI provisioned
  opsapi:
    url: "https://api.example.com"
    namespace: "workstation"       # workspace people must be active members of
    api_key: "${WSL_OPSAPI_API_KEY}"  # opsk_ key of an OpsAPI platform admin
    verify_on_connect: true        # default
```

With the Helm chart: `config.opsapi.enabled=true`, `config.opsapi.url`,
`config.opsapi.namespace`, and `WSL_OPSAPI_API_KEY` in the existing Secret.

**Provision with the uuid.** People are bound by OpsAPI's user uuid, never by
email. OpsAPI's provisioning call must carry it:

```bash
curl -X POST https://vpn.example.com/api/v1/ops/users \
  -H "Authorization: Bearer $OPS_SERVICE_TOKEN" -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","external_id":"<OpsAPI users.uuid>"}'
```

The same call links an account that already exists (a bootstrap administrator,
for instance) when it has no `external_id` yet. A different `external_id` for
an already-linked account is refused with 409.

| Situation | Result |
|---|---|
| Token OpsAPI does not recognise | 401 at sign-in |
| Not an active member of `namespace` | 401 at sign-in |
| SCIM says inactive, or does not know the uuid | 401 at sign-in; 403 at connect (audited) |
| An existing VPN user has the email but no matching `external_id` | 401 — never linked on email |
| `directory` admission and never provisioned | 401 |
| OpsAPI unreachable, or our API key rejected | 503 — never an allow |
| User not provisioned by OpsAPI (no `external_id`) | connect is not checked against OpsAPI |

The desktop app shows **Sign in with OpsAPI** only when `GET /auth/methods`
says the control plane offers it. From a terminal:

```bash
wsl sign-in-methods
wsl login --opsapi --email alice@example.com     # prompts for password, then the code
```

## Planned direction

Today OpsAPI calls WSL. The outbound direction — WSL reading users and groups
from OpsAPI over SCIM, authenticated with an `opsk_` API key — is Phase 2 of the
[implementation plan](IMPLEMENTATION-PLAN.md) and is not built yet.
