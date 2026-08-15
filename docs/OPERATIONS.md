# Operations

## Local stack

```bash
make dev
make down
```

## Health

- `GET /health`
- `GET /metrics` (Prometheus)

## Bootstrap checklist

1. Deploy Postgres + control
2. Configure OIDC
3. Apply GitOps policies/networks
4. Register gateway with registration token
5. Install CLI/desktop, sign in, connect

## Tokens

Rotate `bootstrap.ops_service_token` and `bootstrap.gateway_registration_token` before any non-local use. Tokens are stored hashed (SHA-256).
