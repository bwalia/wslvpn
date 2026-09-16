# Threat Model

## Assets

- WireGuard private keys (device and gateway)
- Session / access tokens
- Policy documents and GitOps commit integrity
- User identity bindings (email, external_id, groups)
- Audit log integrity

## Actors

- End users on managed/unmanaged devices
- Admins via OpsAPI / SCIM / GitOps
- Compromised client or gateway
- Network attackers on the Internet path

## Trust boundaries

1. **IdP → Control**: OIDC identity asserted by configured issuer only.
2. **OpsAPI → Control**: Service token scopes; OpsAPI owns user lifecycle SoT.
3. **Agent → Control**: Bearer access token after OIDC; device registration binds WG pubkey.
4. **Gateway → Control**: A shared secret enrolls a gateway once; from then on
   it holds its own credential. Config is served for the id the credential
   resolves to, not the id in the path, and carries a version and an expiry the
   gateway validates.
5. **Client → Gateway**: WireGuard; authorization already decided by control.

## Key threats and mitigations

| Threat | Mitigation |
|--------|------------|
| Stolen long-lived VPN creds | Short sessions; revoke on disable |
| Policy bypass via UI | GitOps / API only; fail-closed |
| Gateway accepts stale peers | Config version + peer expiry |
| Control-plane outage | Existing lease continues until expiry; no silent extension |
| Key exfiltration from disk | SecureKeyStore; never log private keys |
| Over-broad network access | Resource-scoped policies and AllowedIPs |
| Anonymous read of the overlay topology | Every route names an authorization guard; gateway config needs that gateway's own credential |
| Gateway takeover with the shared enrollment secret | Re-enrolling an existing name requires proof of possession of its current credential |
| One gateway reading another's peers | The config served is for the id the credential resolves to, never the id in the URL |
| Privilege escalation through directory sync | SCIM and ops credentials cannot set a role; provisioned accounts arrive as members |
| Arbitrary file read via GitOps apply | The directory comes from configuration, not the request body |
| Audit history rewritten to hide an action | Append-only triggers, plus a hash chain that makes any edit or deletion detectable |
| Online guessing of tokens or OIDC state | Per-client rate limits on credential-checking endpoints |
| Development back door reaching production | `dev_login_enabled` is explicit, loopback-checked, and refused at startup on a public host |

## Accepted, with reasons

Risks that are understood and not currently mitigated. See
[SECURITY.md](SECURITY.md#known-limits) for the operational consequences.

| Risk | Why it is accepted |
| --- | --- |
| A database superuser can rewrite the audit log | Prevention needs off-box storage; the chain makes it detectable, which is what the application can guarantee |
| Rate limits are per replica | Counters are in process; a global budget belongs at the ingress, where the traffic is already aggregated |
| No organisation boundary | One deployment serves one organisation; tenancy would need per-org identity, IPAM and GitOps |
| Metrics are unauthenticated | Scraped in-cluster and restricted by NetworkPolicy rather than by a credential the scraper would have to hold |

## Out of scope (MVP)

- Hardware attestation / Secure Enclave binding
- Full mTLS agent↔control (API designed to allow later)
- Advanced MDM posture signals beyond basic pass/fail/unknown
