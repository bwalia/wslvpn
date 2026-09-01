# WSL Zero Trust VPN

Lightweight, self-hosted, WireGuard-based Zero Trust access.

> Install the client → sign in with SSO → device is registered → posture is evaluated → policy determines access → WireGuard connects automatically.

## Components

- `wsl-control` — Rust control plane (Axum + PostgreSQL)
- `wsl-gateway` — WireGuard data plane
- `wsl-agent` / `wsl-cli` — endpoint agent and CLI
- `wsl-desktop` — minimal macOS UI

## Quick start (local)

```bash
make dev
```

This starts PostgreSQL (host port **5433**), Dex (OIDC), control plane, and gateway via Docker Compose.

For a host-run control plane against Compose Postgres:

```bash
DATABASE_URL=postgres://wsl:wsl@localhost:5433/wsl cargo run -p wsl-control
cargo run -p wsl-cli -- login --email alice@example.com
cargo run -p wsl-cli -- connect --network development
cargo run -p wsl-cli -- status
```

## Production

The control plane is deployed with the Helm chart in `deploy/helm/wslvpn`:

```bash
helm upgrade --install wslvpn oci://ghcr.io/bwalia/charts/wslvpn \
  --namespace wslvpn --create-namespace \
  --set config.publicUrl=https://vpn.example.com \
  --set ingress.host=vpn.example.com \
  --set config.oidc.issuer=https://idp.example.com \
  --set 'config.adminEmails[0]=security@example.com'
```

Secrets are referenced from a `Secret`, never templated into the chart. On a
fresh database, `config.adminEmails` is the only way an administrator comes into
existence — leave it empty and nobody can reach the administrative API.

See [Operations](docs/OPERATIONS.md) for the bootstrap checklist, backup and
restore, and the runbooks.

## Testing

```bash
make test
```

The control-plane authorization tests drive the real router against a real
database, so `make test` brings a throwaway PostgreSQL up first.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Authorization](docs/AUTHORIZATION.md)
- [Security](docs/SECURITY.md) · [Threat model](docs/THREAT-MODEL.md)
- [Operations](docs/OPERATIONS.md) · [Upgrading](docs/UPGRADING.md) · [Troubleshooting](docs/TROUBLESHOOTING.md)
- [GitOps](docs/GITOPS.md)
- [API](docs/API.md)
- [OpsAPI integration](docs/OPSAPI.md) · [SCIM](docs/SCIM.md) · [OIDC](docs/OIDC.md)

## License

Apache-2.0
