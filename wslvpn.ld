# wslvpn — session log / resume file

Session: 2026-08-15
Goal: build Zero Trust on top of the existing home-lab WireGuard hub, without
disturbing the peers already on it.

## Environment as found

Live hub, 9 peers, mesh `10.8.0.0/24`, peer endpoints on LAN `192.168.1.0/24`:

    10.8.0.4  10.8.0.5  10.8.0.6  10.8.0.7  10.8.0.8
    10.8.0.10 10.8.0.11 10.8.0.14 10.8.0.15

All handshaking within ~2m — treat as production.

## Verdict

Feasible without replacing the hub. `wsl-gateway` drives the `wg` CLI rather
than implementing WireGuard, so it runs as a sidecar on the hub host and manages
only the peers the control plane owns.

## Done this session

Four blockers were identified; three were code and are now fixed. All work is in
`crates/wsl-gateway`. Workspace is green: `cargo clippy --workspace --all-targets
-- -D warnings` clean, 26 tests pass (23 new).

1. **Private-key overwrite (would have broken all 9 peers).**
   `adopt_existing: true` in `wireguard:` config. Skips interface creation,
   listen-port, and private-key write. Config validation rejects
   `adopt_existing` without `public_key`; a private key reaching the apply path
   in adopt mode is a hard error.
   → `crates/wsl-gateway/src/config.rs`, `main.rs`, `apply.rs`

2. **Revocation did not revoke.** `apply.rs` only ever added peers — no
   `wg set … peer … remove` existed, so an expired session's peer stayed on the
   wire forever. Now a real diff against `wg show <iface> dump`:
   add / update / unchanged / remove / foreign.
   → new `crates/wsl-gateway/src/wg.rs`

3. **IPAM collision.** Chose a disjoint range rather than pre-seeding
   reservations: sessions come from `10.8.1.0/24`, hub keeps `10.8.0.0/24`.
   Also makes the "is this peer mine to delete?" test a subnet check.
   → `gitops/examples/networks/zerotrust.yaml`

   Removal is scoped by `wireguard.managed_range`. A peer is eligible only when
   *all* its allowed-ips fall inside it. Straddling / unparseable / `0.0.0.0/0` /
   IPv6-under-v4 all classify as foreign and are never touched. No managed range
   resolves → removal disabled for that cycle, with a warning.

4. **Public endpoint — NOT code, still open.** See "Next" below.

Also fixed in passing:
- nftables rules were appended unconditionally every config version; now checked
  before insert.
- Gateway exited the process on the first heartbeat or apply error. Now logs and
  retries on the next heartbeat with `last_version` intact, so desired state is
  re-attempted rather than lost.
- Heartbeat reported `peer_count: 0` hardcoded; now reports the real count.

## Files

    M crates/wsl-gateway/src/apply.rs      reconcile + adopt guard + nft dedupe
    M crates/wsl-gateway/src/config.rs     adopt_existing, managed_range, validate()
    M crates/wsl-gateway/src/main.rs       adopt guard, retry loop, real peer_count
    M crates/wsl-gateway/Cargo.toml        + ipnetwork 0.20
    M docs/WIREGUARD.md                    reconcile table, adopt mode, bring-up
    ? crates/wsl-gateway/src/wg.rs         NEW — dump parser, plan(), 15 tests
    ? config/gateway.homelab.example.yaml  NEW — adopt-mode template
    ? gitops/examples/networks/zerotrust.yaml  NEW — 10.8.1.0/24

Not committed. Nothing has touched the live hub.

## Next — bring-up, in order

1. Public endpoint. The `192.168.1.x` values in `wg show` are where peers
   connect *from*; the hub has never been dialled from outside the LAN. Need
   DDNS name + UDP/51820 forward, then set `gateway.endpoint` to it.
2. Apply `zerotrust.yaml` via GitOps; read the network UUID from
   `GET /api/v1/networks` into `gateway.network_id`. (Gateways registering
   without one silently fall back to the network named `development`.)
3. Route the new range on the hub: widen the interface address to `10.8.0.1/16`
   or `ip route add 10.8.1.0/24 dev wg0`. Peers are otherwise configured but
   unreachable.
4. Fill `config/gateway.homelab.example.yaml`: `public_key` from
   `wg show wg0 public-key`, control URL, registration token.
5. Run with `manage_interface: false`. Compare the logged plan to `wg show wg0`.
   Expect `foreign: 9` and `add` covering only a test session.
6. Flip `manage_interface: true` (needs root / `CAP_NET_ADMIN`). Verify a 10th
   test peer appears, then revoke it and verify it actually disappears from
   `wg show` — that is the check that #2 above is genuinely fixed.

## Known limitations

- IPAM (`crates/wsl-control/src/services/ipam.rs`) still has no visibility into
  addresses live on the hub. Safe only because the ranges are disjoint. If
  anyone ever points a network at `10.8.0.0/24`, it will hand out colliding
  addresses. Pre-seeding `ipam_allocations` would be the fix.
- `manage_interface: true` has not been exercised against real `wg` — no Linux
  host with WireGuard in this session. Reconcile logic is unit-tested against
  captured dump format; the subprocess calls are not.
- Client side needs no work: `crates/wsl-agent/src/state.rs:106` already writes a
  correct `[Peer]` stanza from control-plane values.
