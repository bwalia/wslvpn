# Architecture

WSL Zero Trust VPN is a self-hosted WireGuard Zero Trust access platform.

## Planes

```mermaid
flowchart TB
  subgraph endpoint [Endpoint Plane]
    Desktop[wsl-desktop]
    CLI[wsl-cli]
    Agent[wsl-agent]
    Desktop --> Agent
    CLI --> Agent
  end

  subgraph control [Control Plane]
    Control[wsl-control]
    PG[(PostgreSQL)]
    Control --> PG
  end

  subgraph data [Data Plane]
    Gateway[wsl-gateway]
    WG[WireGuard]
    Gateway --> WG
  end

  OpsAPI[OpsAPI] -->|service token| Control
  IdP[OIDC IdP] -->|PKCE| Control
  Git[GitOps] -->|apply| Control
  Agent -->|HTTPS| Control
  Gateway -->|register heartbeat| Control
  Agent -->|WireGuard| Gateway
```

## Components

| Component | Role |
|-----------|------|
| `wsl-control` | Identity, devices, policy, sessions, SCIM, OpsAPI provisioning, audit |
| `wsl-gateway` | WireGuard peers, routes, firewall, heartbeat |
| `wsl-agent` | Endpoint auth, device keys, posture, tunnel lifecycle |
| `wsl-cli` | Operator/user CLI over agent IPC |
| `wsl-desktop` | Thin macOS UI over agent |

## Security boundaries

- Control plane is authoritative for access decisions (fail-closed).
- Gateways apply only versioned peer configs from the control plane.
- Private keys never leave secure storage (Keychain / 0600 file fallback for dev).
- Sessions are short-lived; expiry or revoke removes peers.

## Product namespace

Display name: **WSL Zero Trust VPN**. Internal crate prefix: `wsl_*`. Config key `product.namespace` (default `wsl`) allows rebrand without architecture changes.
