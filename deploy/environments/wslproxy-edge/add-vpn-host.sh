#!/usr/bin/env bash
#
# Register vpn.workstation.co.uk on the wslproxy edge (lon1.pop0.uk), routed to
# k3s1's ingress the way the other k3s1 sites are, with an auto-renewing
# Let's Encrypt certificate.
#
# DNS already points the name at the edge (CNAME -> lon1.pop0.uk); this adds
# the edge's side. It follows wslproxy's own workflow — pull the LIVE config,
# edit, push as a dry run to show the diff, then push for real — so the rule
# edit is made to what is actually deployed, not to a stale copy.
#
# Usage (after `wslproxy-cli auth login`, or with WSLPROXY_TOKEN set):
#   WSLPROXY_BASE_URL=https://lon1.pop0.uk deploy/environments/wslproxy-edge/add-vpn-host.sh
#
# Idempotent: re-running with the host already registered changes nothing.
set -euo pipefail

HOST="${HOST:-vpn.workstation.co.uk}"
PROFILE="${PROFILE:-prod}"
# The rule every k3s1 site behind the edge uses ("aws-k3s1-ingress-klipper-80").
RULE_ID="${RULE_ID:-425e4925-8ce1-de5b-2d13-0b086621101f}"
SSL_EMAIL="${SSL_EMAIL:?set SSL_EMAIL — the Let\'s Encrypt contact for $HOST}"
BASE="${WSLPROXY_BASE_URL:?set WSLPROXY_BASE_URL (https://lon1.pop0.uk)}"
CLI="${WSLPROXY_CLI:-wslproxy-cli}"

command -v "$CLI" >/dev/null || { echo "wslproxy-cli not found (see wslproxy docs/wslproxy-cli.md)" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
echo "==> pulling live servers and rules from $BASE"
"$CLI" pull -d "$work" --resources servers,rules --base-url "$BASE"

rule="$work/rules/$PROFILE/$RULE_ID.json"
[ -f "$rule" ] || { echo "rule $RULE_ID not found in profile $PROFILE — refusing to guess an upstream" >&2; exit 1; }
echo "==> upstream: $(jq -r '.name + " -> " + ([.match.response.backends[].address] | join(", "))' "$rule")"

server="$work/servers/$PROFILE/host:$HOST.json"
conf=$(printf '\nserver {\n      listen 80;\n      server_name %s;\n      root /var/www/html;\n      index index.html;\n      access_log logs/%s.access.log;\n      error_log logs/%s.error.log;\n}\n' "$HOST" "$HOST" "$HOST" | base64 | tr -d '\n')
# Same shape as the other k3s1 hosts (e.g. acc-grafana.diytaxreturn.co.uk).
jq -n --arg h "$HOST" --arg p "$PROFILE" --arg r "$RULE_ID" --arg e "$SSL_EMAIL" --arg c "$conf" '{
  id: ("host:" + $h), profile_id: $p, server_name: $h, proxy_server_name: $h,
  proxy_pass: "http://localhost", listens: [{listen: "80"}], root: "/var/www/html",
  index: "index.html", config: $c, config_status: true, rules: [$r],
  match_cases: {}, custom_headers: {}, cache_enabled: false,
  access_log: ("logs/" + $h + ".access.log"), error_log: ("logs/" + $h + ".error.log"),
  dns_record_type: "CNAME", dns_cname_target: "lon1.pop0.uk",
  ssl_enabled: true, ssl_force_https: true, ssl_auto_renew: true, ssl_staging: false,
  ssl_email: $e
}' > "$server"

# Attach the host to the rule, once.
jq --arg id "host:$HOST" '.servers |= (if index([$id]) then . else . + [$id] end)' "$rule" > "$rule.new"
mv "$rule.new" "$rule"

echo "==> dry run"
"$CLI" push -d "$work" --resources servers,rules --base-url "$BASE" --dry-run --diff

read -r -p "Apply this to $BASE? [y/N] " ok
[ "$ok" = y ] || [ "$ok" = Y ] || { echo "not applied"; exit 1; }

"$CLI" push -d "$work" --resources servers,rules --base-url "$BASE" --yes --verify
"$CLI" check nginx --base-url "$BASE"
echo "✔ $HOST registered. The certificate is issued on first HTTPS request; allow a minute."
