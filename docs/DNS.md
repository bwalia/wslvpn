# DNS overrides

The client carries a small DNS resolver, `wsl-dns`, for answering names from a
table you control — the way `/etc/hosts` does, whatever the ISP's resolver (or
the VPN's) would say:

```bash
wsl dns set intranet.example.com 10.0.0.5
wsl dns set intranet.example.com fd00::5      # replaces: one name, one entry
wsl dns set '*.dev.example.com' 10.0.1.1      # every subdomain
wsl dns set tracker.example.net 0.0.0.0       # block
wsl dns apply                                 # turn on (asks for a password once)
wsl dns list
wsl dns query intranet.example.com            # ask the resolver directly
wsl dns remove tracker.example.net
wsl dns disable
```

The desktop app has the same controls under **DNS overrides**.

## How it works

```text
getaddrinfo("intranet.example.com")
  → mDNSResponder reads /etc/resolver/intranet.example.com
      nameserver 127.0.0.1 / port 15353
  → wsl dns serve (launchd agent, runs as you)
      in the table?  answer it (authoritative, TTL 30s)
      otherwise      forward to the nameservers in /etc/resolv.conf
```

Two pieces, with different privileges:

| Piece | Runs as | Changes when |
| --- | --- | --- |
| The resolver, `wsl dns serve` on `127.0.0.1:15353` | you, under launchd (`io.wsl.zerotrust.dns`) | never restarted for an edit: it re-reads `<data dir>/hosts` when it changes |
| One `/etc/resolver/<domain>` file per overridden name, or per wildcard's suffix | root, written by `wsl dns apply` | only when the *set of names* changes |

So changing the address an existing name points to takes effect on the next
lookup with no prompt. Adding a new name asks for a password once, to route it.

The resolver is only ever asked about the routed domains. It does not sit in
front of the system's DNS: if it stops, the overridden names stop resolving and
nothing else is affected, and launchd restarts it.

## Rules

- **An override is total.** A name with an IPv4 override and no IPv6 one gets
  an empty AAAA answer, not the real record from upstream — which a dual-stack
  client would otherwise prefer. The same goes for every other record type:
  forwarding an HTTPS/SVCB record would hand the client the real address in its
  hints.
- **Exact beats wildcard; longer wildcard beats shorter.** `*.example.com` can
  set a default that `api.example.com` refines.
- `*.dev.example.com` covers `a.dev.example.com` and deeper, not
  `dev.example.com` itself.
- A wildcard over a whole TLD (`*.com`) is refused.
- An edit that does not parse is logged and ignored; the previous table stays
  in force, so a typo does not switch every override off.

## Safety

The routed names become file names under `/etc/resolver`, written as root, so
every name is validated as a host name — twice, once when saved and again in
the root-run step — and `../` cannot get through. Every file written carries a
marker line, and only marked files are ever replaced or removed: Docker,
dnsmasq and puma-dev keep their own files in the same directory.

The resolver listens on loopback only, bounds-checks every packet (a fuzz test
flips every byte of a query), and filters upstream replies to the address it
asked.

## Troubleshooting

```bash
wsl dns status                 # enabled, answering, routing up to date?
wsl dns query some.name        # what the resolver itself answers
dscacheutil -q host -a name some.name   # what macOS answers
tail <data dir>/dns.log
```

`dig` bypasses `/etc/resolver`; use `dscacheutil` (or `wsl dns query`) to check.

**Routing: needs `wsl dns apply`** — a name was added but its file has not been
written. Run `wsl dns apply`, or press **Apply** in the app.

**Not available on this platform** — `/etc/resolver` is macOS-only. On Linux,
run `wsl dns serve --listen 127.0.0.1:15353` under your own supervisor and
point systemd-resolved or dnsmasq at it for the domains you override.
