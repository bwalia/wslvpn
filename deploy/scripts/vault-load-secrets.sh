#!/usr/bin/env bash
#
# vault-load-secrets.sh — push one environment's control-plane secrets into
# wslvault's KV v2 mount, so External Secrets can sync them into the cluster.
# Same shape as beaconpulse's loader.
#
# Writes one JSON object to kv/wslvpn/<env>/config:
#   POSTGRES_PASSWORD, WSL_OPS_SERVICE_TOKEN, WSL_GATEWAY_REGISTRATION_TOKEN,
#   WSL_SCIM_SERVICE_TOKEN   generated once, then kept stable
#   WSL_OIDC_CLIENT_SECRET   your Google OAuth client secret
#
# The generated values live in deploy/.secrets/<env>.env (git-ignored, 0600)
# so a re-run writes the same values rather than rotating the database
# password out from under a running Postgres. Delete a line to rotate it.
#
# Usage:
#   VAULT_ADDR=https://vault.workstation.co.uk VAULT_TOKEN=<wslvault-jwt> \
#     deploy/scripts/vault-load-secrets.sh prod
#
# The Google client secret is read from WSL_OIDC_CLIENT_SECRET if set, else
# from the cache, else prompted for without echo — never from an argument,
# which would land in shell history and the process list.
#
# Auth: X-Vault-Token (a wslvault JWT). For header-auth deployments set
#   VAULT_TENANT_ID + VAULT_PRINCIPAL_ID + VAULT_POLICIES instead.
set -euo pipefail

ENV="${1:-}"; [ -n "$ENV" ] || { echo "usage: $0 <env> (prod|…)" >&2; exit 2; }
case "$ENV" in *[!a-z0-9-]*) echo "env must be lowercase letters, digits, dashes" >&2; exit 2;; esac
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADDR="${VAULT_ADDR:?set VAULT_ADDR (e.g. https://vault.workstation.co.uk)}"
CACHE="$REPO/deploy/.secrets/${ENV}.env"

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }

umask 077
mkdir -p "$(dirname "$CACHE")"
touch "$CACHE"; chmod 600 "$CACHE"

cached() { sed -n "s/^$1=//p" "$CACHE" | tail -1; }
remember() { printf '%s=%s\n' "$1" "$2" >> "$CACHE"; }

# ensure KEY BYTES: reuse the cached value, or generate and cache one.
ensure() {
  local v; v="$(cached "$1")"
  if [ -z "$v" ]; then v="$(openssl rand -hex "$2")"; remember "$1" "$v"; fi
  printf '%s' "$v"
}

pg="$(ensure POSTGRES_PASSWORD 24)"
ops="$(ensure WSL_OPS_SERVICE_TOKEN 32)"
gw="$(ensure WSL_GATEWAY_REGISTRATION_TOKEN 32)"
scim="$(ensure WSL_SCIM_SERVICE_TOKEN 32)"

oidc="${WSL_OIDC_CLIENT_SECRET:-$(cached WSL_OIDC_CLIENT_SECRET)}"
if [ -z "$oidc" ]; then
  [ -t 0 ] || { echo "::error::set WSL_OIDC_CLIENT_SECRET (no terminal to prompt on)" >&2; exit 1; }
  read -rs -p "Google OAuth client secret: " oidc; echo
fi
[ -n "$oidc" ] || { echo "::error::the Google client secret is empty; refusing to load a blank" >&2; exit 1; }
[ "$(cached WSL_OIDC_CLIENT_SECRET)" = "$oidc" ] || remember WSL_OIDC_CLIENT_SECRET "$oidc"

obj=$(jq -n --arg p "$pg" --arg o "$ops" --arg g "$gw" --arg s "$scim" --arg c "$oidc" \
  '{POSTGRES_PASSWORD:$p, WSL_OPS_SERVICE_TOKEN:$o, WSL_GATEWAY_REGISTRATION_TOKEN:$g,
    WSL_SCIM_SERVICE_TOKEN:$s, WSL_OIDC_CLIENT_SECRET:$c}')

hdr=(-H "Content-Type: application/json")
if [ -n "${VAULT_TOKEN:-}" ]; then hdr+=(-H "X-Vault-Token: ${VAULT_TOKEN}")
elif [ -n "${VAULT_TENANT_ID:-}" ]; then
  hdr+=(-H "X-Tenant-Id: ${VAULT_TENANT_ID}" -H "X-Principal-Id: ${VAULT_PRINCIPAL_ID:-wslvpn-loader}" -H "X-Policies: ${VAULT_POLICIES:-admin}")
else echo "::error::set VAULT_TOKEN (a wslvault JWT) or VAULT_TENANT_ID/PRINCIPAL_ID/POLICIES" >&2; exit 1; fi

path="wslvpn/${ENV}/config"
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
echo "==> writing $(jq -r 'keys|join(", ")' <<<"$obj") to ${ADDR}/v1/kv/data/${path}"
# The body goes on stdin, not in argv, so the secrets never appear in `ps`.
code=$(jq -nc --argjson d "$obj" '{data:$d}' | curl -s -o "$out" -w '%{http_code}' \
  --connect-timeout 10 --max-time 30 \
  -X POST "${hdr[@]}" --data-binary @- "${ADDR}/v1/kv/data/${path}") || {
  echo "::error::could not reach wslvault at ${ADDR} (curl exit $?). Nothing was written." >&2
  exit 1
}
if [ "$code" = 200 ] || [ "$code" = 204 ]; then
  echo "✔ loaded kv/${path}"
else
  echo "::error::write failed HTTP $code:" >&2; cat "$out" >&2; echo >&2; exit 1
fi
