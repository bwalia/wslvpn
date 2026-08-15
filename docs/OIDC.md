# OIDC

Primary interactive SSO uses Authorization Code Flow with PKCE.

## Config

```yaml
identity:
  oidc:
    issuer: https://login.example.com
    client_id: wsl-client
    scopes: [openid, profile, email]
    redirect_uri: https://control.example.com/auth/oidc/callback
```

## Endpoints

- `GET /auth/oidc/authorize` — start login (stores PKCE verifier)
- `GET /auth/oidc/callback` — code exchange, issues WSL access token

## Local development

Compose runs Dex. For CLI/agent without a browser loop, use:

```bash
POST /auth/dev/login {"email":"alice@example.com"}
```

Dev login is refused unless `server.public_url` points at localhost.

## Production note

MVP decodes `id_token` claims without full JWKS verification for local Dex. Production deployments must verify signatures against the issuer JWKS.
