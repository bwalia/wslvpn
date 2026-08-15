# WireGuard

WSL uses native WireGuard; it does not implement WireGuard cryptography.

## Lifecycle

1. Device registers with control plane (publishes client public key)
2. Policy allows session → IPAM allocates `/32` → peer created on gateway
3. Gateway heartbeats, pulls versioned config, applies peers via `wg`
4. Revoke / disable / expiry deletes peer and frees IP

## Gateway

- Linux first
- `manage_interface: false` logs the reconcile plan without touching the interface
- `manage_interface: true` runs `wg` / `ip` / `nft` (requires privileges)

## Reconciliation

Each config version is applied as a diff against live interface state read from
`wg show <interface> dump`:

| Class | Meaning | Action |
|-------|---------|--------|
| add | desired, absent from interface | `wg set … allowed-ips` |
| update | desired, allowed-ips differ | `wg set … allowed-ips` |
| unchanged | desired, already correct | none |
| remove | managed, no longer desired | `wg set … peer … remove` |
| foreign | outside the managed range | none, ever |

Removal is what makes revocation real: without it an expired session's peer
stays on the wire indefinitely.

### Managed range

`wireguard.managed_range` scopes every destructive action. A live peer is
eligible for removal only when **all** of its allowed-ips fall inside that CIDR.
Anything else — a peer straddling the boundary, an unparseable allowed-ip, a
`0.0.0.0/0` exit peer, an IPv6 peer under an IPv4 range — is classified foreign
and left alone.

When unset it defaults to the network CIDR the control plane serves. When
neither resolves, removal is disabled for that cycle and a warning is logged;
the gateway never falls back to "delete what I don't recognise".

## Adopting an existing hub

`adopt_existing: true` manages peers on an interface that already exists and
already carries peers. The gateway will not create the interface, set its listen
port, or write its private key.

Requires `wireguard.public_key` — the hub's existing public key. Config
validation rejects `adopt_existing` without it, because the gateway would
otherwise generate a fresh keypair and overwrite the private key of every live
peer. A private key reaching the apply path in adopt mode is a hard error, not a
warning.

See [`config/gateway.homelab.example.yaml`](../config/gateway.homelab.example.yaml).

### Bring-up

1. Carve a range disjoint from the existing mesh. With hub peers in
   `10.8.0.0/24`, use `10.8.1.0/24` for sessions — see
   [`gitops/examples/networks/zerotrust.yaml`](../gitops/examples/networks/zerotrust.yaml).
   A disjoint range keeps IPAM from colliding with addresses it cannot see, and
   makes the managed-range test a subnet check.
2. Ensure the hub routes the new range to the interface. Either widen the
   interface address (`10.8.0.1/16`) or add an explicit route:
   `ip route add 10.8.1.0/24 dev wg0`. Without this, peers are configured but
   unreachable.
3. Set `gateway.endpoint` to a **publicly reachable** `host:port`. The endpoints
   in `wg show` are where peers connect *from*; a hub whose peers are all on
   `192.168.1.0/24` has never been dialled from outside the LAN.
4. Set `gateway.network_id` to the zerotrust network's UUID
   (`GET /api/v1/networks`). Gateways registering without one fall back to the
   network named `development`.
5. Run with `manage_interface: false` and compare the logged plan against
   `wg show wg0`. Expect `add` to cover only your test session and `foreign` to
   equal the existing peer count.
6. Flip `manage_interface: true`. The gateway needs root or `CAP_NET_ADMIN`.

## Client

Agent writes `wsl.conf` under the agent data directory for `wg-quick` / Network
Extension integration.
