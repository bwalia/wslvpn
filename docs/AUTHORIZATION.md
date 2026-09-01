# Authorization

Who may call what, and why each rule is where it is.

## The model

Two roles and three kinds of machine credential. Deliberately small: every route
is either "any signed-in user acting on their own resources" or "an
administrator acting on anyone's". A finer hierarchy would need per-resource
ownership rules that do not exist yet, and a role that is defined but not
enforced is worse than no role at all.

| Principal | How it authenticates | Reaches |
| --- | --- | --- |
| `member` | Bearer access token from OIDC | Their own devices, sessions and user record; the network and group lists |
| `admin` | The same, with `role = 'admin'` | Everything below, plus every member's resources |
| Ops service token | Bearer, scope `ops:provision` | `/api/v1/ops/*` only |
| SCIM service token | Bearer, scope `scim:manage` | `/SCIM/v2/*` only |
| Gateway credential | Bearer, bound to one gateway | That gateway's config and heartbeat |

Every handler names its guard in its own signature rather than inheriting one
from a router-level layer. A route added later cannot pick up anonymous access
by omission — it has to say what it requires, or it does not compile with a
`State` extractor alone.

## Becoming an administrator

`bootstrap.admin_emails` is the only source. It is reconciled on **every start**:
an address on the list is granted the role (the account is created if it does
not exist yet), and any admin not on the list is demoted.

Two consequences worth internalising:

- On a fresh database, an empty list means **nobody** can reach the
  administrative API. There is no other path to the first administrator.
- Removing an address is how you revoke the role. Editing `users.role` directly
  works until the next restart, when configuration wins.

An administrator cannot demote, disable or delete **their own** account through
the API. All three would leave a deployment that has to be recovered with a
manual `UPDATE`, and each is far more likely to be a slip than an intention.

## Ownership

A member reading another user's device or session gets **404, not 403**.
Telling an unrelated caller that some id exists is itself a disclosure, so "not
yours" and "not there" are made indistinguishable.

Listing is scoped rather than refused: `GET /api/v1/devices` returns the whole
fleet to an admin and only their own to a member. Refusing outright would make
the endpoint unusable from the client for no security gain.

## Scopes, and what they deliberately exclude

The ops and SCIM credentials are separate, and neither is an administrator's
session:

- A SCIM credential syncs the directory. It cannot read the audit log, revoke a
  session, or reach `/api/v1`.
- An ops credential provisions accounts. It cannot reach `/SCIM/v2` or the
  user-facing API.
- **Neither can set a role.** A SCIM-provisioned account always arrives as a
  member. Roles taken from the directory would make every IdP group mapping a
  privilege-escalation path, so `UpdateUserRequest.role` is hard-wired to `None`
  on both surfaces.

## Gateway credentials

A gateway presents the shared enrollment secret once and receives its own
credential, disclosed exactly then and stored only as a digest.

Two properties matter:

**The verified id wins.** `GET /api/v1/gateways/{id}/config` authenticates the
credential, resolves it to a gateway id, and serves *that* gateway's
configuration — the `{id}` in the path is used for the lookup, never as the
subject of the response. Authenticating one id and acting on another read
separately from the URL is how confused-deputy bugs get in.

**Re-enrollment requires proof of possession.** Registering a name that already
exists needs that gateway's current credential in the `Authorization` header.
Without the rule, anyone holding the shared enrollment secret could re-register
an existing name with a different `endpoint` and pull its traffic to a host they
control. Registering a *new* name still needs only the shared secret.

A gateway with no credential (enrolled before they existed, or one that lost its
state directory) fails closed and re-enrolls.

## The unauthenticated surface

Four things, and nothing else:

| Route | Why |
| --- | --- |
| `/health`, `/livez`, `/readyz` | Probes run before anything can hold a credential |
| `/metrics` | Scraped in-cluster; restrict with NetworkPolicy, not a token |
| `/auth/oidc/*` | The handshake that produces a credential |
| `POST /api/v1/gateways/register` | Authenticates with the enrollment secret in its body |

`/swagger-ui` and `/api-docs/openapi.json` are **not** mounted unless
`server.expose_docs` is true. The document enumerates every route and schema.

`POST /auth/dev/login` mints a session for any email with no credential. It is
gated three times over: an explicit `identity.dev_login_enabled` flag, a
loopback check on `server.public_url`, and a startup validation that refuses to
run a non-loopback deployment with the flag set.

## Testing

`crates/wsl-control/tests/api_authorization.rs` walks every route with no
credential and with an invalid one, and fails if any answers successfully. It is
a list, so a new route is not covered until someone adds it — but the rules it
does cover are asserted against the real router, not a reduced one.
