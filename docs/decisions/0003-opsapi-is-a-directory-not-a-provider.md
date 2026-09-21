# 0003 — OpsAPI is a directory, not an identity provider

**Status:** accepted
**Date:** 2026-09-21

## Context

The intent was for OpsAPI to be the central identity service, with WSLVPN
federating to it over OIDC — an `OPSAPI_ISSUER`, an `OPSAPI_JWKS_URL`, tokens
validated against its published keys.

OpsAPI as built cannot do that. Read from its source rather than assumed:

| Expected | Actual |
|---|---|
| OIDC discovery at `/.well-known/openid-configuration` | Not served. No route matches `well-known` anywhere in the app |
| A JWKS endpoint | None. No `jwks` route exists |
| An `/authorize` endpoint and authorization-code flow | None. There is no OAuth/OIDC provider surface |
| Asymmetric token signing | `HS256` with a shared `JWT_SECRET_KEY` (`helper/jwt-helper.lua`) |
| Standard claims | Claims are nested under a `userinfo` object; `iss` is the literal string `"opsapi"`; there is no `aud` |
| Non-interactive login for a service | Every `/auth/login` requires email-OTP 2FA and returns `requires_2fa` with a session token, never a JWT |

The signing algorithm is the decisive one. `HS256` with a shared secret means
anything that can *validate* an OpsAPI token can also *mint* one. Handing WSLVPN
that secret so it could verify logins would make WSLVPN able to forge them, and
would make a compromise of either system a compromise of both. That is the
opposite of what federation is for.

Two further details matter for any client written against it:

- `/auth/login` reads form-encoded parameters. A JSON body is silently ignored
  and the request fails as though the field were missing — verified against a
  running instance: form-encoded returns `AUTH_INVALID_CREDENTIALS`, the same
  request as JSON returns `VALIDATION_400 field=identifier`.
- The shipped `lapis/api-docs/swagger.json` documents four paths. The application
  serves well over a hundred. It is generated from the database schema and is not
  a usable contract.

## Decision

**Login comes from a standards-compliant OIDC provider. OpsAPI is the directory.**

- A real provider — Dex in development, Entra ID or Keycloak in production —
  issues the tokens WSLVPN validates. WSLVPN is an OIDC relying party and
  verifies signature, `iss`, `aud`, `exp`, `nonce` and `email_verified` against
  the provider's published keys.
- OpsAPI is the source of users and groups, consumed through the SCIM 2.0
  surface it already serves at `/scim/v2/Users` and `/scim/v2/Groups`.
- WSLVPN authenticates to OpsAPI with an API key (`opsk_…`), which is
  namespace-bound and carries scopes, and is refused when presented with another
  namespace's header. This is the credential OpsAPI actually has for
  machine-to-machine use; its interactive login is not usable for one.
- **WSLVPN never holds `JWT_SECRET_KEY` and never validates an OpsAPI JWT.**

## Why not the alternatives

**Put Keycloak in front of OpsAPI, federating to its user store.** Workable, and
OpsAPI already ships `Dockerfile.keycloak` and a `keycloak/` directory. Rejected
for now because OpsAPI enforces its own mandatory email-OTP 2FA on every login,
which would sit alongside Keycloak's MFA as a second, independent OTP system —
two places to enrol, two to lock someone out of. Worth revisiting if OpsAPI's 2FA
becomes optional.

**Build an OIDC provider into OpsAPI.** This is the only option that makes the
original `OPSAPI_JWKS_URL` design real, and it is the largest: discovery,
`/authorize` with consent, code exchange, an RS256 keypair with rotation, and the
replacement of the HS256 shared secret everywhere it is currently trusted. That
is a new security-critical subsystem in Lua inside an Nginx worker. Not ruled
out, but it is its own project with its own review, not a step in this one.

## Consequences

- There is no `OPSAPI_JWKS_URL` or `OPSAPI_ISSUER` in WSLVPN's configuration,
  because there is nothing at the other end of them. The OpsAPI client is
  configured with a base URL, an API key and a namespace.
- Group-driven authorization depends on directory sync being current, not on a
  claim in a login token. Deprovisioning has to revoke sessions explicitly rather
  than relying on the next token refresh to notice.
- The typed OpsAPI client must send form-encoded bodies where OpsAPI expects
  them, parse its `{error: {code, category, context, correlation_id, ...}}`
  envelope, and carry `X-Namespace-Id`/`X-Namespace-Slug`. Its contract tests run
  against a live instance, because the OpenAPI document cannot be trusted as one.

## A note recorded during this review

`middleware/auth.lua` honours an `X-Public-Browse: true` request header by
setting `current_user = nil` and calling the handler anyway. Several routes —
`routes/groups.lua` among them — are wrapped only in `requireAuth`, with no
namespace or permission layer behind it.

This is **not currently exploitable**: the global `before_filter` in `app.lua`
authenticates every request that is not on its public allowlist, so the header
never reaches that branch. Verified against a running instance — `GET
/api/v2/groups` with the header returns `401 Missing Authorization header` from
the global filter.

It is recorded because it is defence-in-depth that currently has nothing behind
it. Adding a route to the global allowlist, or registering one outside the
filter's reach, would turn a dead branch into an unauthenticated write path for
group CRUD — and groups are what WSLVPN policy subjects are built from. Removing
the header check, or making those routes carry a permission layer, would close it
independently of the filter.
