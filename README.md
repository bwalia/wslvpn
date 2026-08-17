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

## Documentation

- [How it works](docs/HOW-IT-WORKS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [Threat model](docs/THREAT-MODEL.md)
- [GitOps](docs/GITOPS.md)
- [API](docs/API.md)
- [OpsAPI integration](docs/OPSAPI.md)

## License

Apache-2.0
