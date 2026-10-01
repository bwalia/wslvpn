# Deployment: control plane on k3s1, gateway on wslproxy-pop1

```text
Mac app ──sign in──▶ https://$HOST (wslproxy edge, TLS → k3s1 traefik-edge → wsl-control ×2 → Postgres)
   │                                   ▲ heartbeat, pulls peer config
   └──WireGuard──▶ wslproxy-pop1:51820 (hub wg interface ◀── wsl-gateway, adopt mode)
```

Nothing secret is in this directory. `__PLACEHOLDERS__` are filled in at deploy
time; every one is listed below.

| Placeholder | Where | What |
| --- | --- | --- |
| `__HOST__` | `k3s1/values.yaml`, `wslproxy-pop1/gateway.yaml` | Control plane's public name |
| `__GOOGLE_CLIENT_ID__` | `k3s1/values.yaml` | Google OAuth client ID (not secret) |
| `__ADMIN_EMAIL__` | `k3s1/values.yaml` | The first administrator's Google account |
| `__GATEWAY_ENDPOINT__` | `wslproxy-pop1/gateway.yaml` | Hub's public `host:port` |
| `__WG_INTERFACE__` | `wslproxy-pop1/*` | `sudo wg show interfaces` on the hub |
| `__HUB_PUBLIC_KEY__` | `wslproxy-pop1/gateway.yaml` | `sudo wg show <if> public-key` |
| `__MANAGED_RANGE__` | `wslproxy-pop1/gateway.yaml` | A /24 disjoint from every existing peer |
| `__FROM_VAULT__` | `wslproxy-pop1/gateway.yaml`, on the host only | `WSL_GATEWAY_REGISTRATION_TOKEN` |
| `__NETWORK_ID__` | `wslproxy-pop1/gateway.yaml` | `GET /api/v1/networks` after step 4 |

## 0. Prerequisites

- **Release `v0.1.0`** — publishes `ghcr.io/bwalia/wsl-control`,
  `ghcr.io/bwalia/wsl-gateway` and the chart `oci://ghcr.io/bwalia/charts/wslvpn`.
  If the GHCR packages are private, make them public or add an image pull
  secret to the `wslvpn` namespace and to Docker on wslproxy-pop1.
- **Google OAuth client** (Web application) with redirect URI
  `https://$HOST/auth/oidc/callback`. See `docs/OIDC.md`, "Google".
- **HTTPS for `$HOST`** comes from the wslproxy edge, like every other site on
  k3s1: the ingress uses the `traefik-edge` class with no TLS block, DNS points
  the name at the edge, and the edge terminates TLS with Let's Encrypt. There
  is no cert-manager on k3s1 and none is needed. Two things to check:
  - external-dns only manages the domains in its `--domain-filter`. If `$HOST`
    is on another domain, create the record yourself, pointing where the
    others do.
  - The control plane must not be reachable except through the edge: bearer
    tokens ride on every request, and the hop from the edge to Traefik is only
    as private as the network it crosses.

## 1. Secrets into wslvault

wslvpn has its own wslvault tenant, `01a0f39f-c438-7681-ac92-8ddfe4848d65`,
read only by the namespaced `wslvault` SecretStore in `k3s1/wslvault-store.yaml`
— not the cluster-wide `wslvault-backend` store, which serves a different
tenant. wslvault keeps each tenant's `kv` separate: an object written with a
key from another tenant succeeds and is invisible here, at the identical path.

### 1a. Load the secrets (once)

```bash
VAULT_ADDR=https://vault.workstation.co.uk \
WSLVAULT_TENANT_ID=01a0f39f-c438-7681-ac92-8ddfe4848d65 \
  deploy/scripts/vault-load-secrets.sh prod
```

It prompts for a wslvault API key from that tenant (`wslv_…`, exchanged for a
short-lived token, with an authenticator code if the key requires MFA) and for
the Google client secret, echoing neither — do not put either on the command
line, where it lands in shell history. It generates the database password and
the three service tokens on your machine, and refuses to write if the key is in
any other tenant. The generated values are cached in `deploy/.secrets/prod.env`
(git-ignored, mode 0600), so re-running it writes the same values instead of
rotating the database password out from under a running Postgres.

Give OpsAPI the `WSL_OPS_SERVICE_TOKEN` from that file; it provisions users
with it. The gateway needs `WSL_GATEWAY_REGISTRATION_TOKEN` (step 5).

### 1b. A machine key for the cluster (once)

External Secrets can only use a pre-issued wslvault token, and an API key
yields one that lasts an hour, so the `wslvault-token-refresh` CronJob
exchanges a machine key for a fresh token every 30 minutes. That key lives in
tenant `01a0f39f-…`, carries only the read-only `wslvpn-read` policy
(`{"paths":["secret/data/wslvpn/**"],"capabilities":["read"]}`, already created)
and does not require MFA.

```bash
kubectl -n wslvpn create secret generic wslvault-session --from-literal=token=   # once
bash deploy/scripts/wslvault-refresher-key.sh     # bash, not zsh
kubectl -n wslvpn patch cronjob wslvault-token-refresh -p '{"spec":{"suspend":false}}'
kubectl -n wslvpn create job --from=cronjob/wslvault-token-refresh wslvault-token-refresh-first
kubectl -n wslvpn logs -f job/wslvault-token-refresh-first   # "refreshed wslvault session for tenant 01a0f39f-…"
```

The script prompts for an admin credential and stores the new key without
printing it. **Which credential matters:** wslvault creates a key in the tenant
of whoever signs in, whatever the request names — so a root or platform key from
another tenant creates it over there. In practice only the bootstrap admin token
(`X-Admin-Token`, in `wslvault/wslvault-mesh-keys`, key `admin-token`) can do
this: a signed-in caller needs the *platform* policy and always mints in its
own tenant, so even a tenant admin in `01a0f39f-…` is refused. The script refuses a signed-in key from another tenant, and checks
the new key's tenant and MFA before storing it; if either is wrong it stores
nothing and prints the key's id to revoke.

Then the store turns Ready and the ExternalSecrets sync within a minute. If the
refresher stops, the store fails within the hour but already-synced Secrets are
kept; running pods are unaffected until it is fixed.

## 2. Namespace, secrets, database

```bash
export KUBECONFIG=~/.kube/k3s1.yaml
kubectl apply -f k3s1/namespace.yaml
kubectl apply -f k3s1/wslvault-store.yaml
kubectl apply -f k3s1/externalsecret.yaml
kubectl -n wslvpn wait externalsecret --all --for=condition=Ready --timeout=2m
kubectl apply -f k3s1/postgres.yaml
kubectl -n wslvpn rollout status statefulset/wslvpn-postgres
```

## 3. Control plane

```bash
HOST=vpn.example.com  # yours
sed "s/__HOST__/$HOST/g; s/__GOOGLE_CLIENT_ID__/<client-id>/; s/__ADMIN_EMAIL__/<you@example.com>/" \
  k3s1/values.yaml > /tmp/wslvpn-values.yaml
helm upgrade --install wslvpn oci://ghcr.io/bwalia/charts/wslvpn --version 0.1.0 \
  -n wslvpn -f /tmp/wslvpn-values.yaml
kubectl -n wslvpn rollout status deploy/wslvpn
curl -fsS https://$HOST/readyz
```

Sign in from the Mac app with `https://$HOST` as the control plane — you are in
`adminEmails`, so you are admitted without being provisioned.

## 4. Network and policy

Create the zero-trust network with a CIDR equal to `__MANAGED_RANGE__`, and a
policy granting your group access, through GitOps or the admin API (see
`gitops/examples/`). Note its id for the gateway.

## 5. Gateway on wslproxy-pop1 — dry run first

```bash
sudo wg show                      # note interface, public key, every peer's allowed-ips
sudo install -d -m 0700 /etc/wsl /var/lib/wsl-gateway
sudo install -m 0600 gateway.yaml /etc/wsl/gateway.yaml   # placeholders filled in
sudo install -m 0644 wsl-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wsl-gateway
sudo journalctl -u wsl-gateway -f
```

With `manage_interface: false` it logs its plan. Expect every existing hub
peer under `foreign` and nothing under `remove`. Only then set
`manage_interface: true` and restart. It never touches peers outside
`managed_range`, the hub's private key, or its listen port.

The hub must route `__MANAGED_RANGE__` to the interface (widen its address or
`ip route add <range> dev <if>`), or peers are configured but unreachable.

## Rollback

- Gateway: `sudo systemctl disable --now wsl-gateway`. Peers it added stay until
  removed; `sudo wg set <if> peer <key> remove` for each in `managed_range`.
- Control plane: `helm -n wslvpn uninstall wslvpn`. The database and its
  backups are separate and survive it.
