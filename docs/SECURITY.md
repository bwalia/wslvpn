# Security

Security is prioritized over convenience.

## Controls

| Area | Control |
| --- | --- |
| Transport | TLS terminated in front of the control plane; it speaks plain HTTP and must never face an untrusted network directly |
| Interactive login | OIDC Authorization Code + PKCE |
| Authorization | Per-route guards, two roles, scoped service credentials — see [AUTHORIZATION.md](AUTHORIZATION.md) |
| Machine credentials | Scoped service tokens, SHA-256 at rest, never readable back |
| Gateways | Per-gateway credentials; re-enrollment requires proof of possession |
| Sessions | 8 hours, revoked on user disable, converge to the data plane on next heartbeat |
| Policy | Fail-closed, first-match wins |
| Audit | Append-only, hash-chained, attributed to the acting principal |
| Rate limiting | Fixed-window per client on credential-checking endpoints |
| Secrets | `${VAR}` from the environment; example values refused on non-loopback deployments |
| Supply chain | `cargo audit` and `cargo deny` as blocking gates; CycloneDX SBOM; cosign-signed image digests |
| Containers | Control plane is distroless nonroot, read-only root, no capabilities |
| Logs | No secrets; failed authorization logged with path and principal |
| Gateway privilege | `CAP_NET_ADMIN` only, and only on the gateway |

## What fails closed

The design choices that decide behaviour when something is wrong:

- **Policy evaluation.** No matching allow rule means deny.
- **Unknown roles.** A `role` value this build does not recognise reads as
  `member`, never as privileged.
- **Missing secrets.** A `${VAR}` with no value is a startup error, not an empty
  string. A blank password that starts is worse than a process that will not.
- **Example secrets on a public host.** The process refuses to start.
- **A gateway with no credential.** Refused, and it re-enrolls.
- **A misconfigured rate limit of zero.** Reads as "no limit configured", so a
  typo cannot lock every client out of the control plane.
- **An unrenderable firewall service row.** Dropped rather than sent, because an
  invalid rule makes `nft` reject the whole ruleset and leaves every *other*
  service unrestricted.

## Key handling

| Platform | Store |
|----------|-------|
| macOS | Keychain (`io.wsl.zerotrust.vpn`) |
| Linux (dev) | Mode `0600` files under agent data dir — **not production** |
| Gateway credential | `<state_dir>/enrollment.json`, mode `0600`, created with those permissions rather than tightened afterwards |

## Known limits

Stated plainly, because a control someone believes in but does not have is worse
than one they know is missing:

- **Rate limits are per replica.** Counters live in process. The effective
  budget is the configured value times the replica count. A global budget needs
  a limiter at the ingress.
- **The audit chain detects tampering; it does not prevent it.** `UPDATE` and
  `DELETE` are refused by trigger, but a principal with enough database
  privilege can disable those triggers. What they cannot do is leave the chain
  verifying afterwards. Ship audit events off-box for prevention.
- **Single-tenant.** There is no organisation boundary in the schema. One
  deployment serves one organisation.
- **`X-Forwarded-For` is not trusted.** The rate limiter keys on the peer
  address only; honouring the header by default would let one client spread
  attempts across unlimited synthetic keys.
- **Revocation lag.** Removing a peer converges on the gateway's next heartbeat,
  within `heartbeat_secs`. Edge proxies caching `sessions/by-ip` add their own
  cache TTL on top.

## Reporting

Report vulnerabilities privately to the maintainers. Do not open public issues
with exploit details.
