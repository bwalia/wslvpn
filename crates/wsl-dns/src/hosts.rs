//! The override table: a hosts file, read the way `/etc/hosts` is read.
//!
//! One line per address, followed by the names it answers for:
//!
//! ```text
//! # comment
//! 10.0.0.5        intranet.example.com wiki.example.com
//! fd00::5         intranet.example.com
//! 10.0.0.9        *.dev.example.com
//! 0.0.0.0         tracker.example.net      # block it
//! ```
//!
//! Two rules make an override an override rather than a suggestion.
//!
//! A name that is overridden is answered entirely from here. If it has an IPv4
//! override and no IPv6 one, an AAAA query gets an empty answer — not the real
//! record from upstream, which a dual-stack client would happily prefer. The
//! same goes for every other record type: an HTTPS/SVCB record from upstream
//! carries address hints of its own, and forwarding it would route around the
//! override just as effectively.
//!
//! And an exact name beats a wildcard, and a longer wildcard beats a shorter
//! one, so `*.example.com` can set a default that `api.example.com` refines.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

/// A name that failed validation, with the line it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// The addresses one name resolves to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    pub addresses: Vec<IpAddr>,
}

impl Records {
    pub fn v4(&self) -> impl Iterator<Item = &IpAddr> {
        self.addresses.iter().filter(|a| a.is_ipv4())
    }

    pub fn v6(&self) -> impl Iterator<Item = &IpAddr> {
        self.addresses.iter().filter(|a| a.is_ipv6())
    }
}

/// One line of the table, as the UI and CLI list and edit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub address: IpAddr,
    /// Lower-case, no trailing dot. A wildcard keeps its leading `*.`.
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    exact: BTreeMap<String, Records>,
    /// Keyed by the suffix after `*.`: `*.dev.example.com` is `dev.example.com`.
    wildcard: BTreeMap<String, Records>,
}

impl Overrides {
    /// Parse a hosts file. Any invalid line fails the whole parse: a resolver
    /// that silently drops the line someone just added is worse than one that
    /// refuses to load and says which line is wrong.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut table = Self::default();
        for (index, raw) in text.lines().enumerate() {
            let line_no = index + 1;
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let address_text = fields.next().unwrap_or_default();
            let address: IpAddr = address_text.parse().map_err(|_| ParseError {
                line: line_no,
                message: format!("`{address_text}` is not an IP address"),
            })?;
            let mut any = false;
            for name in fields {
                any = true;
                let name = normalise(name).map_err(|message| ParseError {
                    line: line_no,
                    message,
                })?;
                table.insert(address, &name);
            }
            if !any {
                return Err(ParseError {
                    line: line_no,
                    message: format!("`{address}` has no names after it"),
                });
            }
        }
        Ok(table)
    }

    fn insert(&mut self, address: IpAddr, name: &str) {
        let (map, key) = match name.strip_prefix("*.") {
            Some(suffix) => (&mut self.wildcard, suffix),
            None => (&mut self.exact, name),
        };
        let records = map.entry(key.to_string()).or_default();
        if !records.addresses.contains(&address) {
            records.addresses.push(address);
        }
    }

    /// The records for `name`, or `None` when the name is not overridden and
    /// should go upstream.
    pub fn lookup(&self, name: &str) -> Option<&Records> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(records) = self.exact.get(&name) {
            return Some(records);
        }
        // Walk up the labels: for a.b.example.com try b.example.com, then
        // example.com, then com. The first hit is the longest suffix.
        let mut rest = name.as_str();
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(records) = self.wildcard.get(parent) {
                return Some(records);
            }
            rest = parent;
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    /// Every entry, one per (address, name) pair, in a stable order.
    pub fn entries(&self) -> Vec<Entry> {
        let exact = self.exact.iter().map(|(n, r)| (n.clone(), r));
        let wild = self.wildcard.iter().map(|(n, r)| (format!("*.{n}"), r));
        exact
            .chain(wild)
            .flat_map(|(name, records)| {
                records.addresses.iter().map(move |address| Entry {
                    address: *address,
                    name: name.clone(),
                })
            })
            .collect()
    }

    /// The domains the operating system has to route to this resolver for the
    /// overrides to be seen at all. A wildcard is routed by its suffix; the
    /// suffix itself, not being overridden, is forwarded upstream from here.
    pub fn routed_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self
            .exact
            .keys()
            .chain(self.wildcard.keys())
            .cloned()
            .collect();
        domains.sort();
        domains.dedup();
        domains
    }

    /// Render back to hosts-file text, one line per entry.
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# Managed by WSL Zero Trust. One address, then the names it answers for.\n",
        );
        for entry in self.entries() {
            out.push_str(&format!("{}\t{}\n", entry.address, entry.name));
        }
        out
    }

    /// Add or replace: `name` answers with `address` alone afterwards.
    pub fn set(&mut self, name: &str, address: IpAddr) -> Result<(), String> {
        let name = normalise(name)?;
        self.remove(&name);
        self.insert(address, &name);
        Ok(())
    }

    /// Remove every entry for `name`. Returns whether there was one.
    pub fn remove(&mut self, name: &str) -> bool {
        let Ok(name) = normalise(name) else {
            return false;
        };
        match name.strip_prefix("*.") {
            Some(suffix) => self.wildcard.remove(suffix).is_some(),
            None => self.exact.remove(&name).is_some(),
        }
    }
}

/// Lower-case a name, drop a trailing dot, and refuse anything that is not a
/// hostname.
///
/// This is not pedantry. The routed domains become file names under
/// `/etc/resolver`, written as root, so a name like `../../etc/sudoers` has to
/// be impossible rather than merely unlikely.
pub fn normalise(name: &str) -> Result<String, String> {
    let lowered = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let (wild, host) = match lowered.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, lowered.as_str()),
    };
    let invalid = || format!("`{name}` is not a valid host name");
    if host.is_empty() || host.len() > 253 {
        return Err(invalid());
    }
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(invalid());
        }
    }
    // A wildcard over a top-level domain would capture everything under it,
    // which is a DNS hijack rather than an override.
    if wild && !host.contains('.') {
        return Err(format!(
            "`{name}` is too broad: a wildcard needs at least two labels"
        ));
    }
    Ok(if wild {
        format!("*.{host}")
    } else {
        host.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_hosts_line_answers_for_every_name_on_it() {
        let t = Overrides::parse("10.0.0.5 intranet.example.com wiki.example.com\n").unwrap();
        assert_eq!(
            t.lookup("intranet.example.com").unwrap().addresses,
            vec![ip("10.0.0.5")]
        );
        assert_eq!(
            t.lookup("wiki.example.com").unwrap().addresses,
            vec![ip("10.0.0.5")]
        );
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let t = Overrides::parse("# header\n\n10.0.0.5 a.example.com # trailing\n   \n").unwrap();
        assert_eq!(t.entries().len(), 1);
    }

    #[test]
    fn lookups_ignore_case_and_the_trailing_dot() {
        let t = Overrides::parse("10.0.0.5 Intranet.Example.com\n").unwrap();
        assert!(t.lookup("INTRANET.example.COM.").is_some());
    }

    #[test]
    fn a_name_with_both_families_keeps_both() {
        let t = Overrides::parse("10.0.0.5 a.example.com\nfd00::5 a.example.com\n").unwrap();
        let r = t.lookup("a.example.com").unwrap();
        assert_eq!(r.v4().count(), 1);
        assert_eq!(r.v6().count(), 1);
    }

    #[test]
    fn a_name_not_in_the_table_goes_upstream() {
        let t = Overrides::parse("10.0.0.5 a.example.com\n").unwrap();
        assert!(t.lookup("b.example.com").is_none());
        // An exact entry does not cover its subdomains; that is what `*.` is for.
        assert!(t.lookup("x.a.example.com").is_none());
    }

    #[test]
    fn a_wildcard_covers_subdomains_but_not_itself() {
        let t = Overrides::parse("10.0.0.9 *.dev.example.com\n").unwrap();
        assert!(t.lookup("api.dev.example.com").is_some());
        assert!(t.lookup("deep.api.dev.example.com").is_some());
        assert!(t.lookup("dev.example.com").is_none());
    }

    #[test]
    fn exact_beats_wildcard_and_longer_wildcard_beats_shorter() {
        let t = Overrides::parse(
            "10.0.0.1 *.example.com\n10.0.0.2 *.dev.example.com\n10.0.0.3 api.dev.example.com\n",
        )
        .unwrap();
        assert_eq!(
            t.lookup("api.dev.example.com").unwrap().addresses,
            vec![ip("10.0.0.3")]
        );
        assert_eq!(
            t.lookup("web.dev.example.com").unwrap().addresses,
            vec![ip("10.0.0.2")]
        );
        assert_eq!(
            t.lookup("www.example.com").unwrap().addresses,
            vec![ip("10.0.0.1")]
        );
    }

    #[test]
    fn a_bad_address_names_its_line() {
        let err =
            Overrides::parse("10.0.0.1 ok.example.com\nnot-an-ip bad.example.com\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.message.contains("not-an-ip"));
    }

    #[test]
    fn an_address_without_names_is_an_error_not_a_no_op() {
        assert_eq!(Overrides::parse("10.0.0.1\n").unwrap_err().line, 1);
    }

    /// These names become files under /etc/resolver, written as root.
    #[test]
    fn names_that_could_escape_a_directory_are_refused() {
        for bad in [
            "../../etc/sudoers",
            "a/b.example.com",
            "..",
            "a..b",
            "-a.com",
            "a b",
            "",
        ] {
            assert!(normalise(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_wildcard_over_a_whole_tld_is_refused() {
        assert!(normalise("*.com").is_err());
        assert_eq!(normalise("*.Example.com.").unwrap(), "*.example.com");
    }

    #[test]
    fn routed_domains_are_exact_names_and_wildcard_suffixes() {
        let t = Overrides::parse(
            "10.0.0.1 a.example.com\n10.0.0.2 *.dev.example.com\n10.0.0.3 a.example.com\n",
        )
        .unwrap();
        assert_eq!(t.routed_domains(), vec!["a.example.com", "dev.example.com"]);
    }

    #[test]
    fn set_replaces_and_remove_forgets() {
        let mut t = Overrides::parse("10.0.0.1 a.example.com\nfd00::1 a.example.com\n").unwrap();
        t.set("A.example.com", ip("10.0.0.2")).unwrap();
        assert_eq!(
            t.lookup("a.example.com").unwrap().addresses,
            vec![ip("10.0.0.2")]
        );
        assert!(t.remove("a.example.com"));
        assert!(!t.remove("a.example.com"));
        assert!(t.is_empty());
    }

    #[test]
    fn render_round_trips() {
        let t =
            Overrides::parse("10.0.0.1 a.example.com b.example.com\n10.0.0.9 *.dev.example.com\n")
                .unwrap();
        assert_eq!(Overrides::parse(&t.render()).unwrap(), t);
    }
}
