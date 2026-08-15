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
4. **Gateway → Control**: Registration token; config must validate version and expiry.
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

## Out of scope (MVP)

- Hardware attestation / Secure Enclave binding
- Full mTLS agent↔control (API designed to allow later)
- Advanced MDM posture signals beyond basic pass/fail/unknown
