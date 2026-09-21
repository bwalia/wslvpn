# 0002 — Multi-tenancy, configuration before schema

**Status:** accepted
**Date:** 2026-09-21
**Supersedes:** [0001 — One deployment serves one organisation](0001-single-tenant-deployments.md)

## Context

ADR-0001 decided this system would stay single-tenant, and its reasoning was
sound on its own terms: adding `org_id` columns while every organisation still
shared one identity provider, one policy directory and one administrator list
would isolate rows and nothing else. It called that a false floor.

Two things have changed.

**The requirement is now real.** WSLVPN is to be an enterprise access platform
with tenant isolation across identity, devices, policy, sessions and audit.
ADR-0001 explicitly said that decision was "a product decision about what this
software is", and it has now been taken the other way.

**The identity platform it integrates with is already multi-tenant.** OpsAPI
models tenancy as *namespaces*: `namespaces`, `namespace_members`,
`namespace_roles` with per-role landing paths, per-namespace permissions,
invitations, ownership transfer, and a namespace switch that reissues the caller's
token. Its API keys are bound to exactly one namespace and are refused when
presented with another namespace's header. So the boundary WSLVPN needs already
exists upstream, with a concrete shape to map onto rather than one to invent.

## Decision

Become multi-tenant, in the order ADR-0001 prescribed: **configuration first,
schema second, query scoping third.** One OpsAPI namespace maps to one WSLVPN
tenant.

Reversing that order is what produces the false floor, so the phases are not
independent and must not be reordered for convenience.

### Phase A — move the single-tenant configuration into the database

The things that make the current deployment singular are all in `control.yaml`:

| Config today | Becomes |
|---|---|
| `identity.oidc` — one issuer, one client | A row per tenant in `identity_providers` (the table exists and is unused) |
| `gitops.path` — one directory | A policy source per tenant |
| `bootstrap.admin_emails` — one list | Tenant-scoped role grants |
| WireGuard address allocation | IPAM per tenant |

Until a request can establish *which* tenant it belongs to before
authentication, nothing later is real. That resolution — host, path prefix, or
the provider a token came from — is the first deliverable, not the last.

### Phase B — schema

`tenant_id` on users, groups, devices, networks, routes, network services,
gateways, policies, sessions, audit events and the OIDC binding table. Five
uniqueness constraints become composite: `users.email`, `users.external_id`,
`groups.name`, network names, gateway names.

### Phase C — scope every query, and prove it

Roughly thirty-five queries. ADR-0001 named the bug class this creates and it
remains the real risk: *a session whose network belongs to one tenant and whose
gateway belongs to another*. That is invisible in ordinary testing and severe in
production.

So cross-tenant access is a test obligation, not a review obligation. Every
resource gets a test that a principal of tenant A cannot read, modify or
reference it from tenant B — modelled on `tests/api_authorization.rs`, which
already walks the whole route table and asserts a negative.

## Consequences

- Two organisations can share a deployment. The isolation boundary moves from
  the deployment to the tenant, and `SECURITY.md` and `THREAT-MODEL.md` must stop
  describing the deployment as the boundary once Phase C lands — and not before.
- The accepted risk "No organisation boundary" leaves the threat model; the risk
  of an incorrectly scoped query enters it.
- Phases A and B are breaking schema and configuration changes and need a
  migration path for existing single-tenant deployments: an implicit "default"
  tenant that existing rows belong to, so an upgrade is not a reinstall.
- Until Phase C is complete and tested, the software is single-tenant with
  tenancy plumbing present. It must not be described as multi-tenant in that
  state, because that is exactly the false floor ADR-0001 warned about.

## What this does not change

Role-based access control within a tenant, per-gateway credentials, scoped
service tokens and ownership checks all stand as built. Tenancy is a boundary
around them, not a replacement for them.
