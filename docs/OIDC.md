# OIDC

Interactive SSO uses the authorization code flow with PKCE. There are two
variants: a browser signing in to the control plane directly, and a native
client — the CLI or the desktop app — that has no browser of its own and no
place to keep a client secret.

## Config

```yaml
identity:
  oidc:
    issuer: https://login.example.com
    client_id: wsl-client
    scopes: [openid, profile, email]
    redirect_uri: https://control.example.com/auth/oidc/callback
    # Optional. Tolerance when comparing a token's exp and iat to local time.
    clock_skew_secs: 60
    # Optional. Where the provider is reachable from the control plane, when
    # that is not the issuer — an in-cluster provider addressed by service DNS
    # while its tokens name the public hostname.
    internal_url: http://dex.identity.svc:5556/dex
```

`redirect_uri` is what the control plane registers with the identity provider.
It does not change for native logins: the provider always returns to the control
plane, which then decides where to send the browser next.

Endpoints are not derived from `issuer`. The control plane reads the provider's
`/.well-known/openid-configuration` and uses the `authorization_endpoint`,
`token_endpoint` and `jwks_uri` it publishes, so a provider that does not lay its
URLs out the way Dex does still works. Discovery is cached for an hour.

`internal_url` exists because an issuer is an identity, not necessarily a
reachable address. When it is set, the token and JWKS endpoints are moved onto
it for the control plane's own requests; the authorization endpoint is left
alone, because that one is for the browser. The issuer itself is still compared
strictly against both the discovery document and every token's `iss` claim — only
the address dialled changes.

## Endpoints

- `GET /auth/oidc/authorize` — start login. Stores the PKCE verifier for the
  handshake with the provider, and for a native login also records where to
  return the browser and the client's own challenge.
- `GET /auth/oidc/callback` — exchanges the provider's code. Returns a token as
  JSON for a browser login, or redirects to the client's loopback address with a
  one-time code for a native one.
- `POST /auth/oidc/exchange` — redeems a one-time code for an access token.
- `POST /auth/dev/login` — local development only, see below.

All four sit behind the credential rate-limit budget rather than the API one.

## Native-app login

The CLI cannot receive a redirect from the provider and cannot hold a secret, so
it proves possession instead. This is the shape RFC 8252 prescribes:

```text
  CLI                     control plane            identity provider
   │  bind 127.0.0.1:0
   │  verifier = random
   │─ authorize(redirect=127.0.0.1:PORT, challenge=SHA256(verifier)) ─▶
   │                            │── authorize(PKCE) ──────────────────▶
   │                            │◀─ code ─────────────────────────────│
   │                            │── token exchange ───────────────────▶
   │                            │◀─ id_token ─────────────────────────│
   │◀── 307 to 127.0.0.1:PORT?code=ONE_TIME ──│
   │─ exchange(code, verifier) ─▶
   │◀── access token ───────────│
```

### What each piece is for

**The redirect allowlist.** `authorize` accepts a `redirect_uri` only if it is
the deployment's configured one or a loopback literal with a port. Anything else
is a 400 and no handshake state is created. Without this, an authorize URL could
be handed to a user and the finished login delivered somewhere the operator
never configured.

**Loopback literals, not names.** `127.0.0.1` and `[::1]` are accepted;
`localhost` is not. A name is resolved by the browser and can be made to resolve
off-machine, which is the attack RFC 8252 section 8.3 describes.

**A code, not a token.** The browser's last hop carries a one-time code with a
two-minute life. A token there would persist in browser history long after the
session it belongs to.

**The client challenge.** The client publishes only `SHA256(verifier)` when the
handshake starts and presents the verifier to redeem. A process that can see
loopback traffic gets the code and still cannot use it. The comparison is
constant-time, and the code row is deleted on any attempt — a wrong verifier
burns the code rather than allowing another guess.

**Hashed at rest.** Only the SHA-256 of the code is stored, as with access
tokens, so a database dump does not hand over pending logins.

## Mobile clients

A phone cannot hold a loopback listener open reliably and cannot stop another
app binding the port first, so it registers a private-use URI scheme instead —
RFC 8252 section 7.1. The rest of the handshake is identical: the same
challenge, the same one-time code, the same exchange.

Nothing is accepted unless the deployment names it:

```yaml
identity:
  oidc:
    native_schemes:
      - io.wsl.zerotrust
```

The schemes are validated at startup. `http`, `https`, `file`, `data` and
`javascript` are refused — accepting any of them here would route around the
loopback rules. A scheme must also be derived from a domain name you control:
`wslvpn` is refused where `io.wsl.zerotrust` is accepted, because private-use
schemes are first come, first served and a bare word is squattable. PKCE means
an intercepted code is worthless without the verifier; the allowlist is what
decides which apps may collect a login at all.

See [iOS](IOS.md).

## Local development

Compose runs Dex. `POST /auth/dev/login {"email": "..."}` mints a token for any
email, which is why it is gated three ways: the `identity.dev_login_enabled`
flag, a loopback check on `server.public_url` at request time, and a config
validator that refuses to start a non-loopback deployment with the flag set.

`wsl login --dev --email you@example.com` uses it. Plain `wsl login` uses the
native flow above and works against a real deployment.

## What is checked before a login is believed

The `id_token` is verified against the provider's published signing keys. Every
one of these is a refusal, not a warning:

| Check | Why |
|---|---|
| Signature, against the `jwks_uri` key named by `kid` | Nothing else establishes that the provider wrote the token |
| Algorithm, against an asymmetric allowlist | A token names its own algorithm in a field the signature does not cover, so `alg: none` and HMAC-the-public-key confusions are refused before a key is chosen |
| `iss` equals the configured issuer | A token from another provider is not a login here |
| `aud` equals `client_id` | A token the provider minted for a *different* application is otherwise accepted — the confused-deputy case |
| `exp`, within `clock_skew_secs` | An expired token is not a login |
| `nonce` matches the one generated for this handshake | Binds the token to this attempt, so a captured one is not replayable |
| `email_verified` is true | At a provider with open self-registration, an unverified address is a claim, not a fact |
| `sub` is present and non-empty | It is half the identity key |

Key rotation is picked up without a restart: an unrecognised `kid` refreshes the
key set, rate limited to once a minute so that tokens bearing random `kid`s
cannot be turned into a stream of requests to the provider.

A rejected token is answered with `401` and no detail. Which check failed is
logged, not returned — the difference between "wrong audience" and "bad
signature" is an oracle worth denying.

## Identity is keyed on the provider's subject, not on email

A login resolves through `oidc_identities`, which binds `(issuer, sub)` to a
user. `sub` is the provider's stable identifier; `email` is stored beside it as a
last-seen attribute for display and audit, and is never an authorization key.

This matters because `bootstrap.admin_emails` grants the admin role by address.
Keying identity on the `email` claim meant any token carrying an administrator's
address became an administrator.

The binding is created on first login. Email is consulted only to attach that
first login to a user the directory already provisioned — otherwise someone
created through SCIM could never sign in — and three rules keep that step from
becoming a takeover path:

- A user who already has a binding for an issuer is never linked to a second
  subject from it. That is the shape of an attacker registering another account
  bearing a victim's address, so it is refused rather than merged.
- Signing in never reactivates a deactivated user. Login is not a provisioning
  decision, and treating it as one silently undoes a deprovisioning.
- A changed address moves with the existing binding instead of matching or
  creating another user.

`crates/wsl-control/tests/oidc_identity_linking.rs` asserts each of these
against a real database; the validation rules themselves are covered in
`auth::oidc_provider`, and `tests/oidc_live_provider.rs` checks them against a
running provider.
