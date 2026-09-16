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
```

`redirect_uri` is what the control plane registers with the identity provider.
It does not change for native logins: the provider always returns to the control
plane, which then decides where to send the browser next.

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

## Local development

Compose runs Dex. `POST /auth/dev/login {"email": "..."}` mints a token for any
email, which is why it is gated three ways: the `identity.dev_login_enabled`
flag, a loopback check on `server.public_url` at request time, and a config
validator that refuses to start a non-loopback deployment with the flag set.

`wsl login --dev --email you@example.com` uses it. Plain `wsl login` uses the
native flow above and works against a real deployment.

## Production note

The `id_token` is currently decoded without JWKS signature verification. It is
received directly from the provider's token endpoint over TLS in the same
request, which OpenID Connect Core section 3.1.3.7 accepts as sufficient for a
confidential client — but it means the control plane cannot validate a token it
did not fetch itself, and there is no defence in depth if the token endpoint URL
is ever wrong. Verifying against the issuer JWKS is still the right end state.
