//! nftables policy for non-HTTP services reachable from the overlay.
//!
//! WSLProxy rules cannot restrict a database or an SSH host — the proxy never
//! sees that traffic. It is restricted here instead.
//!
//! Two properties shape the design:
//!
//! **The gateway owns its own table.** Rules live in `inet wsl_gateway`, never
//! in the host's `filter` table. Replacing our policy cannot disturb whatever
//! the adopted hub already runs, and the same "reconcile only what is ours"
//! rule that governs peers governs the firewall.
//!
//! **Default deny applies to overlay traffic only.** Traffic that did not come
//! from the managed range returns immediately and is left to the host's own
//! chains, so adopting a hub does not silently firewall its existing peers.
//! Overlay traffic that matches no allowed service is dropped.

use std::fmt::Write as _;
use wsl_types::GatewayService;

/// Name of the table the gateway owns. Everything inside it is ours to replace;
/// nothing outside it is ever touched.
pub const TABLE: &str = "wsl_gateway";

/// Render the complete ruleset as an `nft -f -` script.
///
/// The script is idempotent: it deletes and recreates our table on every apply,
/// so the live policy always equals the desired policy with no accumulation.
///
/// `managed_range` scopes the default deny. When it is `None` no policy is
/// emitted at all — refusing to guess which traffic is ours is safer than
/// dropping a hub's existing peers.
pub fn render(
    services: &[GatewayService],
    routes: &[String],
    managed_range: Option<&str>,
) -> Option<String> {
    let range = managed_range?;

    let mut s = String::new();
    // `destroy` would be cleaner but is too new to rely on; `add` then `delete`
    // is the portable way to make this idempotent, since deleting a table that
    // does not exist is an error.
    let _ = writeln!(s, "add table inet {TABLE}");
    let _ = writeln!(s, "delete table inet {TABLE}");
    let _ = writeln!(s, "table inet {TABLE} {{");
    let _ = writeln!(s, "  chain forward {{");
    // priority filter+10 keeps us after the host's own filter rules, so an
    // adopted hub's policy is evaluated first and ours only narrows.
    let _ = writeln!(
        s,
        "    type filter hook forward priority filter + 10; policy accept;"
    );

    // Anything not from the overlay is none of our business.
    let _ = writeln!(s, "    ip saddr != {range} return");

    // Established flows: return traffic for an allowed connection.
    let _ = writeln!(s, "    ct state established,related accept");

    for svc in services {
        if svc.ports.is_empty() {
            continue;
        }
        let ports: Vec<String> = svc.ports.iter().map(|p| p.to_string()).collect();
        let port_expr = if ports.len() == 1 {
            ports[0].clone()
        } else {
            format!("{{ {} }}", ports.join(", "))
        };
        let _ = writeln!(
            s,
            "    ip daddr {} {} dport {} accept comment \"{}\"",
            svc.destination,
            svc.protocol.as_str(),
            port_expr,
            escape_comment(&svc.name),
        );
    }

    // Routes stay reachable for protocols a service entry cannot express (ICMP,
    // and anything an operator routes deliberately). A route is a coarser grant
    // than a service and is listed after them for that reason.
    for route in routes {
        let _ = writeln!(s, "    ip daddr {route} accept");
    }

    // Overlay traffic matching nothing above is denied. This line is the whole
    // point: without it the accept rules above would be decoration on a chain
    // whose policy already accepts.
    let _ = writeln!(s, "    drop");
    let _ = writeln!(s, "  }}");
    let _ = writeln!(s, "}}");

    Some(s)
}

/// nft comments are double-quoted; a quote or backslash inside one would end it
/// early and change the meaning of the rule.
fn escape_comment(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '"' | '\\' => '_',
            other => other,
        })
        .take(63) // nft comment limit
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsl_types::ServiceProtocol;

    fn svc(name: &str, dest: &str, proto: ServiceProtocol, ports: &[u16]) -> GatewayService {
        GatewayService {
            name: name.to_string(),
            destination: dest.to_string(),
            protocol: proto,
            ports: ports.to_vec(),
        }
    }

    const RANGE: &str = "10.8.1.0/24";

    #[test]
    fn no_managed_range_emits_no_policy() {
        // Refusing to guess is safer than dropping an adopted hub's traffic.
        assert!(render(
            &[svc("db", "10.0.0.5/32", ServiceProtocol::Tcp, &[5432])],
            &[],
            None
        )
        .is_none());
    }

    #[test]
    fn non_overlay_traffic_returns_before_any_deny() {
        let out = render(&[], &[], Some(RANGE)).unwrap();
        let ret = out.find("ip saddr != 10.8.1.0/24 return").unwrap();
        let drop = out.find("\n    drop").unwrap();
        assert!(
            ret < drop,
            "return for foreign traffic must precede the drop"
        );
    }

    #[test]
    fn overlay_traffic_is_denied_by_default() {
        let out = render(&[], &[], Some(RANGE)).unwrap();
        assert!(
            out.contains("drop"),
            "an empty service list still denies overlay traffic"
        );
    }

    #[test]
    fn service_becomes_an_accept_rule() {
        let out = render(
            &[svc(
                "postgres",
                "10.0.0.5/32",
                ServiceProtocol::Tcp,
                &[5432],
            )],
            &[],
            Some(RANGE),
        )
        .unwrap();
        assert!(
            out.contains("ip daddr 10.0.0.5/32 tcp dport 5432 accept"),
            "{out}"
        );
        assert!(out.contains("comment \"postgres\""));
    }

    #[test]
    fn multiple_ports_render_as_a_set() {
        let out = render(
            &[svc("web", "10.0.0.6/32", ServiceProtocol::Tcp, &[80, 443])],
            &[],
            Some(RANGE),
        )
        .unwrap();
        assert!(out.contains("tcp dport { 80, 443 } accept"), "{out}");
    }

    #[test]
    fn udp_services_render_as_udp() {
        let out = render(
            &[svc("dns", "10.0.0.53/32", ServiceProtocol::Udp, &[53])],
            &[],
            Some(RANGE),
        )
        .unwrap();
        assert!(out.contains("udp dport 53 accept"), "{out}");
    }

    #[test]
    fn service_without_ports_is_skipped() {
        // `tcp dport` with no port is a syntax error that would fail the whole
        // ruleset, taking every other service down with it.
        let out = render(
            &[
                svc("broken", "10.0.0.7/32", ServiceProtocol::Tcp, &[]),
                svc("good", "10.0.0.8/32", ServiceProtocol::Tcp, &[22]),
            ],
            &[],
            Some(RANGE),
        )
        .unwrap();
        assert!(!out.contains("10.0.0.7/32"), "portless service omitted");
        assert!(out.contains("10.0.0.8/32"), "valid service still rendered");
    }

    #[test]
    fn established_flows_are_accepted() {
        let out = render(&[], &[], Some(RANGE)).unwrap();
        assert!(out.contains("ct state established,related accept"));
    }

    #[test]
    fn ruleset_is_idempotent() {
        // add-then-delete makes re-applying safe whether or not the table
        // already exists, so rules cannot accumulate across config versions.
        let out = render(&[], &[], Some(RANGE)).unwrap();
        let add = out.find("add table inet wsl_gateway").unwrap();
        let del = out.find("delete table inet wsl_gateway").unwrap();
        assert!(add < del, "table is created before it is deleted");
        assert_eq!(
            render(&[], &[], Some(RANGE)).unwrap(),
            out,
            "render is deterministic"
        );
    }

    #[test]
    fn only_our_table_is_touched() {
        let out = render(
            &[svc("db", "10.0.0.5/32", ServiceProtocol::Tcp, &[5432])],
            &["10.0.0.0/24".to_string()],
            Some(RANGE),
        )
        .unwrap();
        // Never reference the host's filter table: an adopted hub's own rules
        // must survive every apply.
        assert!(!out.contains("table inet filter"), "{out}");
        assert!(!out.contains("flush ruleset"), "must never flush globally");
        for line in out
            .lines()
            .filter(|l| l.starts_with("add ") || l.starts_with("delete "))
        {
            assert!(
                line.contains(TABLE),
                "stray statement outside our table: {line}"
            );
        }
    }

    #[test]
    fn routes_are_accepted_after_services() {
        let out = render(
            &[svc("db", "10.0.0.5/32", ServiceProtocol::Tcp, &[5432])],
            &["10.9.0.0/24".to_string()],
            Some(RANGE),
        )
        .unwrap();
        let s = out.find("10.0.0.5/32").unwrap();
        let r = out.find("10.9.0.0/24").unwrap();
        assert!(s < r, "services precede coarser route grants");
    }

    #[test]
    fn comment_cannot_escape_its_quotes() {
        // A name carrying a quote would otherwise terminate the comment and let
        // the rest be read as rule syntax.
        let out = render(
            &[svc(
                "evil\" accept; drop \"",
                "10.0.0.9/32",
                ServiceProtocol::Tcp,
                &[1],
            )],
            &[],
            Some(RANGE),
        )
        .unwrap();
        let comment = out.lines().find(|l| l.contains("comment")).unwrap();
        assert_eq!(
            comment.matches('"').count(),
            2,
            "exactly one quoted comment: {comment}"
        );
    }

    #[test]
    fn comment_strips_control_characters() {
        let out = render(
            &[svc("bad\nname", "10.0.0.9/32", ServiceProtocol::Tcp, &[1])],
            &[],
            Some(RANGE),
        )
        .unwrap();
        let line_count = out.lines().filter(|l| l.contains("10.0.0.9/32")).count();
        assert_eq!(
            line_count, 1,
            "a newline in a name cannot split a rule across lines"
        );
    }

    #[test]
    fn deny_is_the_last_rule() {
        let out = render(
            &[svc("db", "10.0.0.5/32", ServiceProtocol::Tcp, &[5432])],
            &["10.9.0.0/24".to_string()],
            Some(RANGE),
        )
        .unwrap();
        let chain: Vec<&str> = out
            .lines()
            .map(|l| l.trim())
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with('}')
                    && !l.starts_with("chain")
                    && !l.starts_with("table")
            })
            .collect();
        assert_eq!(
            *chain.last().unwrap(),
            "drop",
            "drop must be last: {chain:?}"
        );
    }
}
