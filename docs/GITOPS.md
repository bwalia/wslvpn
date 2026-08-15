# GitOps

Git is the preferred configuration source for policies, networks, and groups.

## Layout

```text
gitops/
├── groups/
├── networks/
├── policies/
└── environments/   # optional overlays
```

## Apply

Control plane bootstraps from `gitops.path` on startup when `gitops.enabled: true`.

```bash
curl -X POST http://localhost:8080/api/v1/gitops/apply \
  -H 'Content-Type: application/json' \
  -d '{"path":"./gitops/examples","git_commit":"abc123"}'
```

Or apply a single policy:

```bash
curl -X POST http://localhost:8080/api/v1/policies/apply \
  -H 'Content-Type: application/json' \
  -d '{"yaml":"...","git_commit":"abc123"}'
```

Policies are versioned. Access decisions record `policy_id`, `policy_version`, and `git_commit` in audit events.

## Drift

Compare Git desired `current_version` / commit with control-plane `policies` table. UI may display drift but must not invent unmanaged config when GitOps is enabled.
