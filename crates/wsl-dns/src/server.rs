//! The resolver: answer from the override table, forward everything else.
//!
//! It listens on loopback, UDP and TCP on the same port, and runs as the user.
//! macOS sends it only the domains named in `/etc/resolver` (see
//! [`crate::resolver`]), so it never sits in front of the whole system's DNS —
//! if it stops, the overridden names stop resolving and nothing else notices.
//!
//! The table is re-read when the file changes, so an edit takes effect on the
//! next query without a restart. A table that fails to parse is logged and the
//! previous one kept: a typo should not turn every override off at once.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::hosts::Overrides;
use crate::wire::{self, ParseError};

/// The name the health probe asks for. Answered locally, never forwarded, so a
/// probe proves this resolver is up rather than that some resolver is.
pub const PROBE_NAME: &str = "health.wsl-zerotrust.invalid";

/// How long to wait for one upstream before trying the next.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

/// A TCP client gets this long to send its query.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Where forwarded queries go.
#[derive(Debug, Clone)]
pub enum Upstreams {
    Fixed(Vec<SocketAddr>),
    /// The `nameserver` lines of a resolv.conf, re-read on every forward so a
    /// network change — or the VPN's own DNS coming up — is followed.
    ResolvConf(PathBuf),
}

impl Upstreams {
    fn resolve(&self, own: SocketAddr) -> Vec<SocketAddr> {
        let all = match self {
            Upstreams::Fixed(list) => list.clone(),
            Upstreams::ResolvConf(path) => std::fs::read_to_string(path)
                .map(|t| parse_resolv_conf(&t))
                .unwrap_or_default(),
        };
        // Never forward to ourselves: that is a loop, not a lookup.
        all.into_iter().filter(|a| *a != own).collect()
    }
}

/// The nameservers in a resolv.conf, on port 53.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "nameserver").then_some(())?;
            // A scoped IPv6 address (fe80::1%en0) cannot be parsed as an
            // IpAddr; drop the scope rather than the server.
            let addr = fields.next()?.split('%').next()?;
            addr.parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub hosts: PathBuf,
    pub upstreams: Upstreams,
    /// TTL on synthesised answers. Short, so an edit is not cached for long.
    pub ttl: u32,
}

struct Table {
    overrides: Overrides,
    modified: Option<SystemTime>,
}

struct Shared {
    config: Config,
    own: SocketAddr,
    table: RwLock<Table>,
}

pub struct Server {
    udp: UdpSocket,
    tcp: TcpListener,
    shared: Arc<Shared>,
}

impl Server {
    /// Bind both sockets. With port 0 the kernel picks one for UDP and TCP
    /// takes the same number, retrying if something else already holds it.
    pub async fn bind(config: Config) -> Result<Self> {
        let mut attempts = 0;
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind(config.listen)
                .await
                .with_context(|| format!("binding UDP {}", config.listen))?;
            let addr = udp.local_addr()?;
            match TcpListener::bind(addr).await {
                Ok(tcp) => break (udp, tcp),
                Err(e) if config.listen.port() == 0 && attempts < 10 => {
                    attempts += 1;
                    tracing::debug!(%e, "tcp port taken, retrying");
                }
                Err(e) => return Err(e).with_context(|| format!("binding TCP {addr}")),
            }
        };
        let own = udp.local_addr()?;
        let overrides = load(&config.hosts)?;
        let shared = Arc::new(Shared {
            table: RwLock::new(Table {
                overrides,
                modified: modified(&config.hosts),
            }),
            config,
            own,
        });
        Ok(Self { udp, tcp, shared })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.shared.own
    }

    /// Serve until the task is dropped.
    pub async fn run(self) -> Result<()> {
        let udp = Arc::new(self.udp);
        let tcp_shared = self.shared.clone();
        let tcp = self.tcp;
        let tcp_task = tokio::spawn(async move {
            loop {
                match tcp.accept().await {
                    Ok((stream, _)) => {
                        let shared = tcp_shared.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_tcp(stream, shared).await {
                                tracing::debug!(%e, "tcp client");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(%e, "tcp accept"),
                }
            }
        });

        let mut buf = vec![0u8; 4096];
        let result = loop {
            let (len, peer) = match udp.recv_from(&mut buf).await {
                Ok(v) => v,
                // ICMP port-unreachable from a previous reply surfaces here on
                // some platforms; it is about that client, not this socket.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(e) => break Err(e.into()),
            };
            let query = buf[..len].to_vec();
            let shared = self.shared.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                if let Some(reply) = handle(&shared, &query, Transport::Udp).await {
                    let _ = udp.send_to(&reply, peer).await;
                }
            });
        };
        tcp_task.abort();
        result
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

async fn serve_tcp(mut stream: TcpStream, shared: Arc<Shared>) -> Result<()> {
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }
        let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
        tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut query)).await??;
        if let Some(reply) = handle(&shared, &query, Transport::Tcp).await {
            stream
                .write_all(&(reply.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(&reply).await?;
        }
    }
}

/// One query in, at most one reply out.
async fn handle(shared: &Shared, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
    let question = match wire::parse_query(query) {
        Ok(q) => q,
        Err(ParseError::Truncated) => return None,
        Err(ParseError::Malformed { id, rcode }) => return Some(wire::error_for_id(id, rcode)),
    };
    if question.name.eq_ignore_ascii_case(PROBE_NAME) {
        return Some(wire::answer(&question, &[], 0));
    }

    refresh(shared).await;
    {
        let table = shared.table.read().await;
        if let Some(records) = table.overrides.lookup(&question.name) {
            tracing::debug!(name = %question.name, qtype = question.qtype, "override");
            return Some(wire::answer(
                &question,
                &records.addresses,
                shared.config.ttl,
            ));
        }
    }

    let upstreams = shared.config.upstreams.resolve(shared.own);
    for upstream in &upstreams {
        let result = match transport {
            Transport::Udp => forward_udp(*upstream, query, question.id).await,
            Transport::Tcp => forward_tcp(*upstream, query).await,
        };
        match result {
            Ok(reply) => return Some(reply),
            Err(e) => tracing::debug!(%upstream, %e, "upstream failed"),
        }
    }
    tracing::warn!(name = %question.name, tried = upstreams.len(), "no upstream answered");
    Some(wire::error(&question, wire::RCODE_SERVFAIL))
}

async fn forward_udp(upstream: SocketAddr, query: &[u8], id: u16) -> Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind).await?;
    // connect() filters replies to the upstream's address, so a spoofed reply
    // from anywhere else is never read.
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + UPSTREAM_TIMEOUT;
    loop {
        let len = tokio::time::timeout_at(deadline, socket.recv(&mut buf))
            .await
            .context("timed out")??;
        if len >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            buf.truncate(len);
            return Ok(buf);
        }
    }
}

async fn forward_tcp(upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let work = async {
        let mut stream = TcpStream::connect(upstream).await?;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(query).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).await?;
        anyhow::Ok(reply)
    };
    tokio::time::timeout(UPSTREAM_TIMEOUT, work)
        .await
        .context("timed out")?
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// A missing file is an empty table, not an error: no overrides yet.
fn load(path: &Path) -> Result<Overrides> {
    match std::fs::read_to_string(path) {
        Ok(text) => Overrides::parse(&text).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Overrides::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

async fn refresh(shared: &Shared) {
    let now = modified(&shared.config.hosts);
    if shared.table.read().await.modified == now {
        return;
    }
    let mut table = shared.table.write().await;
    if table.modified == now {
        return;
    }
    table.modified = now;
    match load(&shared.config.hosts) {
        Ok(overrides) => {
            tracing::info!(entries = overrides.entries().len(), "reloaded overrides");
            table.overrides = overrides;
        }
        Err(e) => tracing::error!("{e:#}; keeping the previous overrides"),
    }
}

/// Ask a resolver at `addr` for the probe name. True if it answered.
pub async fn probe(addr: SocketAddr) -> bool {
    let attempt = async {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(addr).await?;
        socket
            .send(&wire::build_query(0x5a5a, PROBE_NAME, wire::TYPE_A))
            .await?;
        let mut buf = [0u8; 512];
        let len = socket.recv(&mut buf).await?;
        anyhow::Ok(wire::parse_response(&buf[..len]).is_some_and(|r| r.id == 0x5a5a))
    };
    matches!(
        tokio::time::timeout(Duration::from_millis(500), attempt).await,
        Ok(Ok(true))
    )
}

/// Resolve `name` against the resolver at `addr`, over UDP.
pub async fn query(addr: SocketAddr, name: &str, qtype: u16) -> Result<wire::Response> {
    let socket = UdpSocket::bind(if addr.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .await?;
    socket.connect(addr).await?;
    let id = rand_id();
    socket.send(&wire::build_query(id, name, qtype)).await?;
    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .context("no answer within 3s")??;
    let response = wire::parse_response(&buf[..len]).context("unreadable response")?;
    anyhow::ensure!(response.id == id, "response id did not match the query");
    Ok(response)
}

fn rand_id() -> u16 {
    // Not security-relevant (loopback, connected socket); just not constant.
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 16)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_nameservers_are_read_on_port_53() {
        let text = "# comment\nsearch lan\nnameserver 192.168.1.1\nnameserver fe80::1%en0\nnameserver ::1\noptions x\n";
        let got = parse_resolv_conf(text);
        assert_eq!(
            got,
            vec![
                "192.168.1.1:53".parse().unwrap(),
                "[fe80::1]:53".parse().unwrap(),
                "[::1]:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn the_resolver_never_forwards_to_itself() {
        let own: SocketAddr = "127.0.0.1:15353".parse().unwrap();
        let ups = Upstreams::Fixed(vec![own, "10.0.0.1:53".parse().unwrap()]);
        assert_eq!(ups.resolve(own), vec!["10.0.0.1:53".parse().unwrap()]);
    }
}
