# 0004 — Signing in with OpsAPI by asking OpsAPI

**Status:** accepted
**Date:** 2026-10-23
**Builds on:** [ADR-0003](0003-opsapi-is-a-directory-not-a-provider.md)

## Context

People want to sign in to the VPN with the OpsAPI account they already use, and
to have OpsAPI and its SCIM directory decide — before every connection — whether
they still may.

ADR-0003 explains why WSLVPN cannot verify an OpsAPI token itself: tokens are
HS256 under a shared `JWT_SECRET_KEY`, and anything able to verify one can mint
one. That is still true and still decisive. What ADR-0003 did not use is that
OpsAPI will answer the question for us:

| Endpoint | Credential | Answers |
|---|---|---|
| `GET /auth/me` | the person's session token | whose live session this is, whether the account is active, and which workspaces they are an *active* member of (`NamespaceQueries.getForUser` filters on `nm.status = 'active' AND n.status = 'active'`) |
| `GET /scim/v2/Users/{uuid}` | an `opsk_` key of a platform administrator | the directory record: email and `active` |

Both were confirmed against a running OpsAPI (`401 {"error":"Invalid or expired
token"}` for a bad session, `401 {"error":"Invalid API key"}` for a bad key,
`AUTH_INVALID_CREDENTIALS` in the error envelope for a bad password, form-encoded
only). OpsAPI's SCIM `GET /scim/v2/Users` ignores `filter`, so lookup is by uuid,
which `/auth/me` supplies.

## Decision

**Verify an OpsAPI sign-in by asking OpsAPI, twice, from two directions, and
bind the person by OpsAPI's uuid — never by email.**

1. The app sends email and password to **OpsAPI** (`/auth/login`, then
   `/auth/2fa/verify` with the emailed code when the workspace requires one).
   The control plane never receives the password.
2. The app gives the resulting OpsAPI token to `POST /auth/opsapi/exchange`.
3. The control plane calls `/auth/me` with it. Unknown session, deactivated
   account, or not an active member of `identity.opsapi.namespace` → refused.
   OpsAPI has open sign-up; an account alone is not membership.
4. The control plane calls SCIM with **its own** key. Unknown, inactive, or an
   email that disagrees with `/auth/me` → refused. A failure of our key or of
   OpsAPI is a 503, never an allow.
5. The person is bound as `(opsapi:<url>, <uuid>)` in `oidc_identities`. A first
   sign-in finds a user whose `external_id` is that uuid — one OpsAPI
   provisioned — or, under `jit` admission and only when no user has the email,
   creates one. **An existing user is never linked on email**: OpsAPI does not
   require a verified address to register, so "an OpsAPI account carrying
   alice's address" is not alice.
6. The control plane issues its own access token. The OpsAPI token is used for
   those requests and dropped — not stored, not logged.
7. On every `POST /api/v1/sessions`, a user with an OpsAPI `external_id` is
   looked up over SCIM again; inactive or unknown → 403 with an audit record,
   OpsAPI unreachable → 503. Users OpsAPI did not provision are not consulted.

To attach an account that predates OpsAPI (a bootstrap administrator, say),
OpsAPI's provisioning call `POST /api/v1/ops/users` with the same email and its
uuid as `external_id` links it. That call carries the directory's service
credential, which is what makes it a statement about identity. A different
`external_id` for an already-linked account is a 409, never a silent re-link.

## Consequences

- The control plane briefly holds a person's OpsAPI session token, which is a
  bearer credential for OpsAPI. It is sent only back to OpsAPI's own `/auth/me`
  and never persisted. A compromised control plane could replay tokens that pass
  through it during the compromise; it still cannot mint them.
- OpsAPI is on the connect path. When it is down, OpsAPI-provisioned users cannot
  start new sessions (existing ones are unaffected). `verify_on_connect: false`
  trades that for slower deprovisioning; the default is to fail closed.
- The SCIM key belongs to an OpsAPI platform administrator, because OpsAPI's SCIM
  routes require that role. It is a powerful credential; it lives in the
  deployment's Secret like the others and is never sent to clients
  (`/auth/methods` publishes only the URL and workspace).
- A plain WireGuard server reached with an imported `.conf` has no server-side
  hook to ask anyone, so these checks apply to connections through the control
  plane. A client-side "check before connecting" for a raw config would be
  advisory only — the private key is in the file — and is deliberately not
  offered as if it were access control.
