# 0001 — One deployment serves one organisation

**Status:** superseded by [0002 — Multi-tenancy, configuration first](0002-multi-tenancy-config-first.md)
**Date:** 2026-09-01

> Superseded on 2026-09-21. The requirement this ADR called hypothetical became
> real, and OpsAPI turned out to model tenancy already, as namespaces. The
> reasoning below still holds on its own terms and ADR-0002 follows the
> sequencing it prescribes — configuration before schema — for exactly the
> reason given here.

## Context

An enterprise-readiness review raised multi-tenancy: there is no organisation
boundary in the schema, so every user, group, network, gateway and policy in a
deployment shares one namespace.

## Decision

Keep the system single-tenant. One deployment serves one organisation.

## Why

**The product's own configuration is single-tenant, and tenancy in the schema
alone would be a false floor.** `identity.oidc` names one issuer and one client.
`gitops.path` names one directory. `bootstrap.admin_emails` names one set of
administrators. Adding `org_id` columns and scoping the queries would isolate
*rows* while every organisation still shared one identity provider, one policy
source and one administrator list — isolation that reads as real in the schema
and is not real in operation. That is worse than not having it, because it
invites people to rely on it.

Doing tenancy properly means per-organisation identity providers (the
`identity_providers` table exists but is unused), per-organisation policy
sources, per-organisation IPAM, and a way for a request to establish which
organisation it belongs to before authentication. That is a product decision
about what this software is, not a schema migration.

**Nothing about enterprise deployment requires it.** Self-hosted zero-trust
network access is deployed per organisation — Headscale, Netbird self-hosted and
Firezone self-hosted all work this way. An enterprise runs its own instance
against its own IdP. The isolation boundary is the deployment.

**The cost is not the columns.** It is roughly thirty-five queries that must be
scoped correctly, five uniqueness constraints that become composite, and a class
of bug — a session whose network belongs to one organisation and whose gateway
belongs to another — that is invisible in testing and severe in production. That
risk is worth taking against a real requirement and not worth taking against a
hypothetical one.

## Consequences

- The isolation boundary is the deployment. Two organisations means two
  deployments and two databases.
- `SECURITY.md` and `THREAT-MODEL.md` state this as a known limit rather than
  leaving readers to infer it.
- Should tenancy become a requirement, the work starts with the configuration
  model — moving identity and GitOps sources into the database, per organisation
  — and not with the schema. Reversing that order produces the false floor
  described above.

## What was built instead

Role-based access control within the single tenant: two roles, scoped service
credentials, per-gateway credentials, and ownership checks so a member reaches
only their own resources. That addresses the access-control gap the review
actually found, which was that there was no authorization at all rather than
that it was insufficiently partitioned.
