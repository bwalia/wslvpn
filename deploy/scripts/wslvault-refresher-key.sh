#!/usr/bin/env bash
#
# wslvault-refresher-key.sh — create the machine key the wslvault token
# refresher uses (k3s1/wslvault-store.yaml) and store it in the cluster,
# without ever printing it.
#
#   bash deploy/scripts/wslvault-refresher-key.sh
#
# (Run it with bash. zsh's `read -p` means something else entirely.)
#
# The key must live in wslvpn's tenant, carry only the read-only `wslvpn-read`
# policy, and not require MFA — nothing is there to type a code. wslvault
# decides the tenant from the credential that creates it:
#
#   - A signed-in key (wslv_...) mints only inside its OWN tenant, whatever the
#     request says. So it has to be an admin key in wslvpn's tenant; a root or
#     platform key from another tenant silently creates the key over there.
#     This script refuses to try that.
#   - The bootstrap admin token (X-Admin-Token) may name any tenant.
#
# Whatever happens, the new key is checked before it is stored: it must sign
# in to TENANT, without MFA. If not, nothing is stored and its id is printed
# so it can be revoked.
set -euo pipefail

VAULT="${VAULT_ADDR:-https://vault.workstation.co.uk}"
TENANT="${TENANT:-01a0f39f-c438-7681-ac92-8ddfe4848d65}"
POLICY="${POLICY:-wslvpn-read}"
NAME="${NAME:-wslvpn-eso-refresher}"
NS="${NS:-wslvpn}"
SECRET="${SECRET:-wslvault-api-key}"

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
command -v kubectl >/dev/null || { echo "kubectl required" >&2; exit 1; }

if kubectl -n "$NS" get secret "$SECRET" >/dev/null 2>&1; then
  echo "secret $NS/$SECRET already exists; delete it first to replace it"; exit 0
fi

# post PATH JSON [HEADER] -> "<body>\n<status>"; the body goes on stdin.
post() {
  printf '%s' "$2" | curl -s -m 20 -w '\n%{http_code}' -X POST \
    -H 'Content-Type: application/json' ${3:+-H "$3"} --data-binary @- "$VAULT$1"
}
body() { sed '$d' <<<"$1"; }
status() { tail -1 <<<"$1"; }
# Describe a response without any secret-bearing field.
safe() { body "$1" | jq -c 'if type=="object" then del(.token, .key, .challenge, .api_key) else . end' 2>/dev/null || body "$1" | head -c 200; }

# Prompted without echo; WSLVAULT_ADMIN_CREDENTIAL / WSLVAULT_TOTP for CI.
CRED="${WSLVAULT_ADMIN_CREDENTIAL:-}"
if [ -z "$CRED" ]; then
  read -rs -p "admin credential (wslv_ admin key in the tenant, or the bootstrap admin token): " CRED </dev/tty; echo
fi
[ -n "$CRED" ] || { echo "nothing entered" >&2; exit 1; }

case "$CRED" in
  wslv_*)
    R=$(post /v1/auth/api-key "$(jq -nc --arg k "$CRED" '{api_key:$k}')"); unset CRED
    [ "$(status "$R")" = 200 ] || { echo "sign-in failed: HTTP $(status "$R") $(safe "$R")" >&2; exit 1; }
    if [ "$(body "$R" | jq -r '.mfa_required // false')" = true ]; then
      CODE="${WSLVAULT_TOTP:-}"
      [ -n "$CODE" ] || read -r -p "authenticator code: " CODE </dev/tty
      R=$(post /v1/auth/mfa/totp "$(jq -nc --arg c "$(body "$R" | jq -r .challenge)" --arg t "$CODE" '{challenge:$c,code:$t}')")
      [ "$(status "$R")" = 200 ] || { echo "code refused: HTTP $(status "$R") $(safe "$R")" >&2; exit 1; }
    fi
    signed_in=$(body "$R" | jq -r '.tenant_id // empty')
    echo "signed in: tenant ${signed_in:-?}, policies $(body "$R" | jq -c '.policies // []')"
    if [ "$signed_in" != "$TENANT" ]; then
      echo "::error::this key is in tenant ${signed_in:-?}; a signed-in key can only create keys in its own tenant." >&2
      echo "Use an admin key from tenant $TENANT, or the bootstrap admin token. Nothing was created." >&2
      exit 1
    fi
    AUTH="Authorization: Bearer $(body "$R" | jq -r .token)"; unset R
    ;;
  *)
    AUTH="X-Admin-Token: $CRED"; unset CRED
    ;;
esac

R=$(post /v1/api-keys "$(jq -nc --arg n "$NAME" --arg t "$TENANT" --arg p "$POLICY" \
  '{name:$n, tenant_id:$t, policies:[$p], mfa_required:false}')" "$AUTH"); unset AUTH
[ "$(status "$R")" = 200 ] || [ "$(status "$R")" = 201 ] || {
  echo "::error::key not created: HTTP $(status "$R") $(safe "$R")" >&2; exit 1; }
KEY=$(body "$R" | jq -r '.key // empty')
ID=$(body "$R" | jq -r '.id // empty'); unset R
case "$KEY" in wslv_*) ;; *) echo "::error::no key in the response" >&2; exit 1;; esac

# Check what was actually created before it goes anywhere.
C=$(post /v1/auth/api-key "$(jq -nc --arg k "$KEY" '{api_key:$k}')")
got_tenant=$(body "$C" | jq -r '.tenant_id // empty')
got_mfa=$(body "$C" | jq -r '.mfa_required // false')
got_policies=$(body "$C" | jq -c '.policies // []'); unset C
if [ "$got_mfa" = true ] || [ "$got_tenant" != "$TENANT" ]; then
  unset KEY
  echo "::error::the new key signs in to tenant ${got_tenant:-?} (mfa_required=$got_mfa); expected $TENANT without MFA." >&2
  echo "Not stored. Revoke it: DELETE $VAULT/v1/api-keys/$ID" >&2
  exit 1
fi
echo "new key $ID signs in to tenant $got_tenant with $got_policies, no MFA"

printf %s "$KEY" | kubectl -n "$NS" create secret generic "$SECRET" --from-file=api_key=/dev/stdin
unset KEY
echo "stored as $NS/$SECRET. Start the refresher:"
echo "  kubectl -n $NS patch cronjob wslvault-token-refresh -p '{\"spec\":{\"suspend\":false}}'"
echo "  kubectl -n $NS create job --from=cronjob/wslvault-token-refresh wslvault-token-refresh-first"
