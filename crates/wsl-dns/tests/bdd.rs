//! Step definitions for tests/features/*.feature.
//!
//! Everything here is real: two resolvers on loopback sockets, one standing in
//! for the ISP and one for ours, and lookups sent as DNS packets. Nothing is
//! mocked below the socket.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use cucumber::{given, then, when, World};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use wsl_dns::hosts::Overrides;
use wsl_dns::wire::{self, Response};
use wsl_dns::{Config, Server, Upstreams};

#[derive(Debug, Default, World)]
struct Dns {
    dir: Option<PathBuf>,
    isp: Vec<(String, IpAddr)>,
    isp_down: bool,
    isp_task: Option<JoinHandle<()>>,
    isp_addr: Option<SocketAddr>,
    ours: Overrides,
    our_task: Option<JoinHandle<()>>,
    our_addr: Option<SocketAddr>,
    last: Option<Response>,
}

impl Drop for Dns {
    fn drop(&mut self) {
        for task in [self.isp_task.take(), self.our_task.take()]
            .into_iter()
            .flatten()
        {
            task.abort();
        }
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl Dns {
    fn dir(&mut self) -> PathBuf {
        self.dir
            .get_or_insert_with(|| {
                let dir = std::env::temp_dir().join(format!(
                    "wsl-dns-bdd-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&dir).unwrap();
                dir
            })
            .clone()
    }

    fn hosts_path(&mut self) -> PathBuf {
        self.dir().join("hosts")
    }

    fn write_ours(&mut self) {
        let path = self.hosts_path();
        write_bumping_mtime(&path, &self.ours.render());
    }

    /// Start the ISP (unless it is down) and our resolver in front of it.
    async fn ensure_started(&mut self) -> SocketAddr {
        if let Some(addr) = self.our_addr {
            return addr;
        }
        let upstream = if self.isp_down {
            // A port nothing listens on: the upstream exists but never answers.
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = socket.local_addr().unwrap();
            drop(socket);
            addr
        } else {
            let isp_hosts = self.dir().join("isp-hosts");
            let text: String = self.isp.iter().map(|(n, a)| format!("{a} {n}\n")).collect();
            std::fs::write(&isp_hosts, text).unwrap();
            let isp = Server::bind(Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                hosts: isp_hosts,
                upstreams: Upstreams::Fixed(vec![]),
                ttl: 300,
            })
            .await
            .expect("isp bind");
            let addr = isp.local_addr();
            self.isp_task = Some(tokio::spawn(async move {
                let _ = isp.run().await;
            }));
            self.isp_addr = Some(addr);
            addr
        };

        self.write_ours();
        let ours = Server::bind(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            hosts: self.hosts_path(),
            upstreams: Upstreams::Fixed(vec![upstream]),
            ttl: 30,
        })
        .await
        .expect("bind");
        let addr = ours.local_addr();
        self.our_task = Some(tokio::spawn(async move {
            let _ = ours.run().await;
        }));
        self.our_addr = Some(addr);
        addr
    }
}

/// Write, then make sure the modification time moved. Two writes inside one
/// filesystem timestamp tick would otherwise look like no change at all.
fn write_bumping_mtime(path: &std::path::Path, text: &str) {
    let before = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    std::fs::write(path, text).unwrap();
    if let Some(before) = before {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        let mut t = before + std::time::Duration::from_secs(1);
        let now = std::fs::metadata(path).unwrap().modified().unwrap();
        if now > t {
            t = now;
        }
        file.set_modified(t).unwrap();
    }
}

#[given(expr = "the ISP's resolver says {string} is {string}")]
fn isp_says(w: &mut Dns, name: String, address: String) {
    w.isp.push((name, address.parse().unwrap()));
}

#[given("the ISP's resolver is down")]
fn isp_down(w: &mut Dns) {
    w.isp_down = true;
}

#[given(expr = "my overrides say {string} is {string}")]
fn overrides_say(w: &mut Dns, name: String, address: String) {
    // A name can carry both families, as in a hosts file.
    let text = format!("{}{} {}\n", w.ours.render(), address, name);
    w.ours = Overrides::parse(&text).unwrap();
    if w.our_addr.is_some() {
        w.write_ours();
    }
}

#[when(expr = "I change my overrides so {string} is {string}")]
fn change_override(w: &mut Dns, name: String, address: String) {
    w.ours.set(&name, address.parse().unwrap()).unwrap();
    w.write_ours();
}

#[when(expr = "I break my overrides file with {string}")]
fn break_overrides(w: &mut Dns, line: String) {
    let path = w.hosts_path();
    let text = format!("{}{line}\n", w.ours.render());
    write_bumping_mtime(&path, &text);
}

fn qtype(kind: &str) -> u16 {
    match kind {
        "A" => wire::TYPE_A,
        "AAAA" => wire::TYPE_AAAA,
        other => panic!("unknown record type {other}"),
    }
}

#[when(expr = "I look up the {word} record for {string}")]
async fn look_up(w: &mut Dns, kind: String, name: String) {
    let addr = w.ensure_started().await;
    w.last = Some(
        wsl_dns::server::query(addr, &name, qtype(&kind))
            .await
            .expect("an answer"),
    );
}

#[when(expr = "I look up the {word} record for {string} over TCP")]
async fn look_up_tcp(w: &mut Dns, kind: String, name: String) {
    let addr = w.ensure_started().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let query = wire::build_query(0x7777, &name, qtype(&kind));
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&query).await.unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.unwrap();
    let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).await.unwrap();
    let response = wire::parse_response(&reply).expect("a readable response");
    assert_eq!(response.id, 0x7777);
    w.last = Some(response);
}

#[then(expr = "I get {string}")]
fn i_get(w: &mut Dns, address: String) {
    let r = w.last.as_ref().expect("a lookup");
    assert_eq!(r.rcode, wire::RCODE_NOERROR, "{r:?}");
    assert_eq!(r.addresses, vec![address.parse::<IpAddr>().unwrap()]);
}

#[then("I get no addresses and no error")]
fn i_get_nodata(w: &mut Dns) {
    let r = w.last.as_ref().expect("a lookup");
    assert_eq!(r.rcode, wire::RCODE_NOERROR, "{r:?}");
    assert!(r.addresses.is_empty(), "{r:?}");
}

#[then("the lookup fails with SERVFAIL")]
fn servfail(w: &mut Dns) {
    let r = w.last.as_ref().expect("a lookup");
    assert_eq!(r.rcode, wire::RCODE_SERVFAIL, "{r:?}");
}

#[tokio::main]
async fn main() {
    Dns::cucumber()
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
