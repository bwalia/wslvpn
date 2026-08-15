# WireGuard

WSL uses native WireGuard; it does not implement WireGuard cryptography.

## Lifecycle

1. Device registers with control plane (publishes client public key)
2. Policy allows session → IPAM allocates `/32` → peer created on gateway
3. Gateway heartbeats, pulls versioned config, applies peers via `wg`
4. Revoke / disable / expiry deletes peer and frees IP

## Gateway

- Linux first
- `manage_interface: false` logs desired peers (Compose default)
- `manage_interface: true` runs `wg` / `ip` / `nft` (requires privileges)

## Client

Agent writes `wsl.conf` under the agent data directory for `wg-quick` / Network Extension integration.
