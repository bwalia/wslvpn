//! Just enough of the DNS wire format (RFC 1035) to answer from a table.
//!
//! The resolver reads one thing out of a query — its single question — and
//! writes one kind of response: that question echoed back with zero or more
//! A/AAAA answers. Everything it does not answer itself it forwards as opaque
//! bytes, so there is no need to understand the rest of the protocol, and no
//! reason to parse what is only going to be relayed.
//!
//! Every read is bounds-checked. The input is a datagram from whoever can reach
//! the socket, and a resolver that panics on a short packet is a resolver
//! anyone on the machine can switch off.

use std::net::IpAddr;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NOTIMP: u8 = 4;

const HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    /// Dotted, as sent (case preserved), without a trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Opcode and RD, which a response has to echo.
    flags: u16,
    /// The raw question section, echoed verbatim so the client's 0x20 case
    /// randomisation survives the round trip.
    raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Too short to hold even a header: nothing to reply to.
    Truncated,
    /// A header, but not a query we can answer. Carries the id so the client
    /// gets an error rather than a timeout.
    Malformed { id: u16, rcode: u8 },
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]))
}

/// Read the question out of a query.
pub fn parse_query(buf: &[u8]) -> Result<Question, ParseError> {
    if buf.len() < HEADER_LEN {
        return Err(ParseError::Truncated);
    }
    let id = u16_at(buf, 0).ok_or(ParseError::Truncated)?;
    let flags = u16_at(buf, 2).ok_or(ParseError::Truncated)?;
    let malformed = |rcode| ParseError::Malformed { id, rcode };

    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    if is_response {
        return Err(malformed(RCODE_FORMERR));
    }
    if opcode != 0 {
        return Err(malformed(RCODE_NOTIMP));
    }
    if u16_at(buf, 4) != Some(1) {
        return Err(malformed(RCODE_FORMERR));
    }

    let mut at = HEADER_LEN;
    let mut labels: Vec<String> = Vec::new();
    let mut name_len = 0usize;
    loop {
        let len = *buf.get(at).ok_or(malformed(RCODE_FORMERR))? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        // Compression pointers and the reserved label types have no business
        // in a question; a client does not compress the only name it sends.
        if len & 0xc0 != 0 {
            return Err(malformed(RCODE_FORMERR));
        }
        let label = buf.get(at..at + len).ok_or(malformed(RCODE_FORMERR))?;
        name_len += len + 1;
        if name_len > 255 {
            return Err(malformed(RCODE_FORMERR));
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        at += len;
    }
    let qtype = u16_at(buf, at).ok_or(malformed(RCODE_FORMERR))?;
    let qclass = u16_at(buf, at + 2).ok_or(malformed(RCODE_FORMERR))?;
    let end = at + 4;

    Ok(Question {
        id,
        name: labels.join("."),
        qtype,
        qclass,
        flags: flags & 0x7900, // opcode + RD
        raw: buf[HEADER_LEN..end].to_vec(),
    })
}

/// A response to `question` carrying `addresses`, filtered to the family the
/// question asked for. An empty filtered set is a NODATA answer: the name
/// exists, and has no record of that type.
pub fn answer(question: &Question, addresses: &[IpAddr], ttl: u32) -> Vec<u8> {
    let records: Vec<&IpAddr> = match question.qtype {
        TYPE_A => addresses.iter().filter(|a| a.is_ipv4()).collect(),
        TYPE_AAAA => addresses.iter().filter(|a| a.is_ipv6()).collect(),
        _ => Vec::new(),
    };
    let records: Vec<&IpAddr> = if question.qclass == CLASS_IN {
        records
    } else {
        Vec::new()
    };
    let mut out = header(question, RCODE_NOERROR, true, records.len() as u16);
    out.extend_from_slice(&question.raw);
    for address in records {
        // 0xc00c: a pointer back to the question's name at offset 12.
        out.extend_from_slice(&[0xc0, 0x0c]);
        match address {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&TYPE_A.to_be_bytes());
                out.extend_from_slice(&CLASS_IN.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&CLASS_IN.to_be_bytes());
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// An error response. With a parsed question it is echoed; without one the
/// response carries only the header.
pub fn error(question: &Question, rcode: u8) -> Vec<u8> {
    let mut out = header(question, rcode, false, 0);
    out.extend_from_slice(&question.raw);
    out
}

/// An error response to a query that could not be parsed past its header.
pub fn error_for_id(id: u16, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(0x8080u16 | rcode as u16).to_be_bytes()); // QR, RA
    out.extend_from_slice(&[0; 8]);
    out
}

fn header(question: &Question, rcode: u8, authoritative: bool, answers: u16) -> Vec<u8> {
    let mut flags: u16 = 0x8000 | question.flags | 0x0080 | rcode as u16; // QR, RA
    if authoritative {
        flags |= 0x0400;
    }
    let mut out = Vec::with_capacity(HEADER_LEN + question.raw.len() + answers as usize * 28);
    out.extend_from_slice(&question.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    out
}

/// Build a query. The server does not need this; tests, the health probe and
/// the CLI's `dns query` do.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(label.len().min(63) as u8);
        out.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// What a response said, for a client that only cares about addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: u16,
    pub rcode: u8,
    pub authoritative: bool,
    pub addresses: Vec<IpAddr>,
}

/// Read the A/AAAA answers out of a response. Other record types are skipped.
pub fn parse_response(buf: &[u8]) -> Option<Response> {
    let id = u16_at(buf, 0)?;
    let flags = u16_at(buf, 2)?;
    if flags & 0x8000 == 0 {
        return None;
    }
    let qd = u16_at(buf, 4)?;
    let an = u16_at(buf, 6)?;
    let mut at = HEADER_LEN;
    for _ in 0..qd {
        at = skip_name(buf, at)? + 4;
    }
    let mut addresses = Vec::new();
    for _ in 0..an {
        at = skip_name(buf, at)?;
        let rtype = u16_at(buf, at)?;
        let rdlen = u16_at(buf, at + 8)? as usize;
        let data = buf.get(at + 10..at + 10 + rdlen)?;
        match (rtype, rdlen) {
            (TYPE_A, 4) => addresses.push(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
            (TYPE_AAAA, 16) => addresses.push(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
            _ => {}
        }
        at += 10 + rdlen;
    }
    Some(Response {
        id,
        rcode: (flags & 0x000f) as u8,
        authoritative: flags & 0x0400 != 0,
        addresses,
    })
}

fn skip_name(buf: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *buf.get(at)?;
        if len == 0 {
            return Some(at + 1);
        }
        if len & 0xc0 == 0xc0 {
            buf.get(at + 1)?;
            return Some(at + 2);
        }
        at += 1 + len as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_query_round_trips_through_the_parser() {
        let q = parse_query(&build_query(0xbeef, "Intranet.Example.com", TYPE_A)).unwrap();
        assert_eq!(q.id, 0xbeef);
        assert_eq!(q.name, "Intranet.Example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
    }

    #[test]
    fn an_a_answer_carries_only_the_ipv4_addresses() {
        let q = parse_query(&build_query(7, "a.example.com", TYPE_A)).unwrap();
        let bytes = answer(&q, &[ip("10.0.0.5"), ip("fd00::5")], 30);
        let r = parse_response(&bytes).unwrap();
        assert_eq!(r.id, 7);
        assert_eq!(r.rcode, RCODE_NOERROR);
        assert!(r.authoritative);
        assert_eq!(r.addresses, vec![ip("10.0.0.5")]);
    }

    #[test]
    fn an_aaaa_answer_carries_only_the_ipv6_addresses() {
        let q = parse_query(&build_query(7, "a.example.com", TYPE_AAAA)).unwrap();
        let r = parse_response(&answer(&q, &[ip("10.0.0.5"), ip("fd00::5")], 30)).unwrap();
        assert_eq!(r.addresses, vec![ip("fd00::5")]);
    }

    /// An override with no record of the asked-for type is NODATA — never a
    /// fall-through to the real record.
    #[test]
    fn a_missing_family_is_an_empty_noerror_answer() {
        let q = parse_query(&build_query(7, "a.example.com", TYPE_AAAA)).unwrap();
        let r = parse_response(&answer(&q, &[ip("10.0.0.5")], 30)).unwrap();
        assert_eq!(r.rcode, RCODE_NOERROR);
        assert!(r.addresses.is_empty());
    }

    #[test]
    fn the_question_is_echoed_byte_for_byte() {
        let query = build_query(9, "MiXeD.example.com", TYPE_A);
        let q = parse_query(&query).unwrap();
        let resp = answer(&q, &[], 30);
        assert_eq!(&resp[12..query.len()], &query[12..]);
    }

    #[test]
    fn recursion_desired_is_echoed() {
        let q = parse_query(&build_query(1, "a.example.com", TYPE_A)).unwrap();
        let resp = answer(&q, &[], 30);
        assert_eq!(resp[2] & 0x01, 0x01, "RD not echoed");
        assert_eq!(resp[3] & 0x80, 0x80, "RA not set");
    }

    #[test]
    fn short_packets_are_rejected_not_panicked_on() {
        for len in 0..12 {
            assert_eq!(parse_query(&vec![0; len]), Err(ParseError::Truncated));
        }
    }

    #[test]
    fn every_truncation_of_a_valid_query_is_handled() {
        let full = build_query(3, "a.b.example.com", TYPE_A);
        for len in 12..full.len() {
            assert!(matches!(
                parse_query(&full[..len]),
                Err(ParseError::Malformed { id: 3, .. })
            ));
        }
    }

    #[test]
    fn a_compression_pointer_in_the_question_is_formerr() {
        let mut q = build_query(4, "a.example.com", TYPE_A);
        q[12] = 0xc0;
        assert_eq!(
            parse_query(&q),
            Err(ParseError::Malformed {
                id: 4,
                rcode: RCODE_FORMERR
            })
        );
    }

    #[test]
    fn a_response_or_a_non_query_opcode_is_refused() {
        let mut q = build_query(5, "a.example.com", TYPE_A);
        q[2] |= 0x80;
        assert_eq!(
            parse_query(&q),
            Err(ParseError::Malformed {
                id: 5,
                rcode: RCODE_FORMERR
            })
        );
        let mut q = build_query(5, "a.example.com", TYPE_A);
        q[2] |= 0x10; // opcode 2, STATUS
        assert_eq!(
            parse_query(&q),
            Err(ParseError::Malformed {
                id: 5,
                rcode: RCODE_NOTIMP
            })
        );
    }

    #[test]
    fn error_responses_keep_the_id() {
        let r = parse_response(&error_for_id(0x1234, RCODE_SERVFAIL)).unwrap();
        assert_eq!((r.id, r.rcode), (0x1234, RCODE_SERVFAIL));
        let q = parse_query(&build_query(0x55, "a.example.com", TYPE_A)).unwrap();
        let r = parse_response(&error(&q, RCODE_SERVFAIL)).unwrap();
        assert_eq!((r.id, r.rcode), (0x55, RCODE_SERVFAIL));
    }

    /// A cheap fuzz: every byte flipped in every position must not panic.
    #[test]
    fn corrupted_queries_never_panic() {
        let base = build_query(6, "www.example.com", TYPE_AAAA);
        for i in 0..base.len() {
            for b in [0x00, 0x3f, 0x40, 0xc0, 0xff] {
                let mut q = base.clone();
                q[i] = b;
                let _ = parse_query(&q);
                let _ = parse_response(&q);
            }
        }
    }
}
