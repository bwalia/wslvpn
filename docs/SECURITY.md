# Security

Security is prioritized over convenience.

## Requirements (MVP)

- TLS for all control-plane traffic in production
- OIDC Authorization Code + PKCE for interactive login
- Service tokens (hashed at rest) for OpsAPI / M2M provisioning
- Short-lived sessions and device certificates
- Device and user revocation immediately revoke WireGuard peers
- Fail-closed policy evaluation
- No plaintext private keys in config files
- No secrets in logs
- Strict input validation on routes, CIDRs, and peer keys
- Minimal privileges on gateway (`CAP_NET_ADMIN` only where required)

## Key handling

| Platform | Store |
|----------|-------|
| macOS | Keychain (`io.wsl.zerotrust.vpn`) |
| Linux (dev) | Mode `0600` files under agent data dir — **not production** |

## Reporting

Report vulnerabilities privately to the maintainers. Do not open public issues with exploit details.
