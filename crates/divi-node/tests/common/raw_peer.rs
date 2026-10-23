// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A regtest node listening on loopback and a scripted peer that speaks the
//! wire protocol byte by byte, so tests can send what an honest node never
//! would. Every wait is bounded.

#![allow(dead_code)]

use divi_node::config::NodeConfig;
use divi_node::Node;
use divi_primitives::ChainMode;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

/// Regtest network magic
pub const MAGIC: [u8; 4] = [0xa1, 0xcf, 0x7e, 0xac];
pub const PROTOCOL_VERSION: i32 = 70920;

/// How long to wait for something that should happen
pub const WAIT: Duration = Duration::from_secs(10);
/// How long to watch for something that should not happen
pub const QUIET: Duration = Duration::from_secs(3);

pub struct TestNode {
    pub node: Node,
    pub port: u16,
    _dir: tempfile::TempDir,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl TestNode {
    /// A started regtest node listening on 127.0.0.1, with no outbound peers
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(edit: impl FnOnce(&mut NodeConfig)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let mut config = NodeConfig::regtest(ChainMode::Divi);
        config.data_dir = dir.path().to_path_buf();
        config.p2p.listen_addr = "127.0.0.1".into();
        config.p2p.port = port;
        config.p2p.listen = Some(true);
        config.p2p.enable_discovery = false;
        edit(&mut config);
        let node = Node::new(config).unwrap();
        node.start().await.unwrap();
        // The listener comes up on a spawned task
        tokio::time::timeout(WAIT, async {
            while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("node listens");
        TestNode {
            node,
            port,
            _dir: dir,
        }
    }

    /// The misbehaviour score of the (single) peer connected from `ip`
    pub fn score(&self, ip: IpAddr) -> Option<i32> {
        self.node
            .peer_manager()
            .scoring()
            .all_stats()
            .into_iter()
            .find(|s| s.ip == ip)
            .map(|s| s.misbehavior_score)
    }

    /// Wait (bounded) until the peer from `ip` has exactly `score`
    pub async fn wait_score(&self, ip: IpAddr, score: i32) -> Option<i32> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let now = self.score(ip);
            if now == Some(score) || tokio::time::Instant::now() >= deadline {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub fn banned(&self, ip: IpAddr) -> bool {
        self.node.peer_manager().is_banned(&ip)
    }
}

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    divi_crypto::double_sha256(data)
}

pub fn compact(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// A framed message
pub fn frame(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&cmd);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha256d(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

fn net_addr() -> Vec<u8> {
    let mut v = 1u64.to_le_bytes().to_vec();
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
    v.extend_from_slice(&51476u16.to_be_bytes());
    v
}

/// A full `version` payload
pub fn version_payload(version: i32, nonce: u64, user_agent: &[u8]) -> Vec<u8> {
    let mut v = version.to_le_bytes().to_vec();
    v.extend_from_slice(&1u64.to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    v.extend_from_slice(&now.to_le_bytes());
    v.extend_from_slice(&net_addr());
    v.extend_from_slice(&net_addr());
    v.extend_from_slice(&nonce.to_le_bytes());
    v.extend_from_slice(&compact(user_agent.len() as u64));
    v.extend_from_slice(user_agent);
    v.extend_from_slice(&0i32.to_le_bytes());
    v.push(1);
    v
}

/// `count` inventory items of `inv_type`
pub fn inv_payload(inv_type: u32, count: usize) -> Vec<u8> {
    let mut v = compact(count as u64);
    for i in 0..count {
        v.extend_from_slice(&inv_type.to_le_bytes());
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        v.extend_from_slice(&hash);
    }
    v
}

#[derive(Debug, PartialEq, Eq)]
pub enum Recv {
    Message(String, Vec<u8>),
    Closed,
    Timeout,
}

pub struct RawPeer {
    pub stream: TcpStream,
    pub ip: IpAddr,
}

impl RawPeer {
    /// Connect from `src` (any 127.0.0.0/8 address works on loopback)
    pub async fn connect(node: &TestNode, src: &str) -> Self {
        let ip: IpAddr = src.parse().unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(ip, 0)).unwrap();
        let stream = tokio::time::timeout(
            WAIT,
            socket.connect(SocketAddr::from(([127, 0, 0, 1], node.port))),
        )
        .await
        .expect("connect in time")
        .unwrap();
        RawPeer { stream, ip }
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) {
        // A peer that dropped us shows up on the next read, not here
        let _ = self.stream.write_all(bytes).await;
        let _ = self.stream.flush().await;
    }

    pub async fn send(&mut self, command: &str, payload: &[u8]) {
        self.send_raw(&frame(command, payload)).await;
    }

    /// The next message, or Closed / Timeout
    pub async fn recv(&mut self, within: Duration) -> Recv {
        let read = async {
            let mut header = [0u8; 24];
            if self.stream.read_exact(&mut header).await.is_err() {
                return Recv::Closed;
            }
            let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; len];
            if self.stream.read_exact(&mut payload).await.is_err() {
                return Recv::Closed;
            }
            let end = header[4..16].iter().position(|&b| b == 0).unwrap_or(12);
            let command = String::from_utf8_lossy(&header[4..4 + end]).into_owned();
            Recv::Message(command, payload)
        };
        tokio::time::timeout(within, read)
            .await
            .unwrap_or(Recv::Timeout)
    }

    /// The payload of the next `command` message within `within` (others skipped)
    pub async fn expect(&mut self, command: &str, within: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.recv(left).await {
                Recv::Message(c, p) if c == command => return Some(p),
                Recv::Message(..) => continue,
                Recv::Closed | Recv::Timeout => return None,
            }
        }
    }

    /// True if the node closes the connection within `within`
    pub async fn closed_within(&mut self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.recv(left).await {
                Recv::Message(..) => continue,
                Recv::Closed => return true,
                Recv::Timeout => return false,
            }
        }
    }

    /// Send `version`, wait for the node's `version` and `verack`, send `verack`
    pub async fn handshake(&mut self) {
        self.send(
            "version",
            &version_payload(PROTOCOL_VERSION, rand_nonce(), b"/raw:1/"),
        )
        .await;
        assert!(self.expect("version", WAIT).await.is_some(), "node version");
        assert!(self.expect("verack", WAIT).await.is_some(), "node verack");
        self.send("verack", &[]).await;
    }

    /// True if the connection is still up: a ping gets its pong
    pub async fn alive(&mut self) -> bool {
        let nonce = rand_nonce();
        self.send("ping", &nonce.to_le_bytes()).await;
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.recv(left).await {
                Recv::Message(c, p) if c == "pong" && p == nonce.to_le_bytes() => return true,
                Recv::Message(..) => continue,
                Recv::Closed | Recv::Timeout => return false,
            }
        }
    }
}

pub fn rand_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    t ^ 0x9e37_79b9_7f4a_7c15
}

/// Parse a `reject` payload into (message, code, reason)
pub fn parse_reject(p: &[u8]) -> (String, u8, String) {
    let ml = p[0] as usize;
    let message = String::from_utf8_lossy(&p[1..1 + ml]).into_owned();
    let code = p[1 + ml];
    let rl = p[2 + ml] as usize;
    let reason = String::from_utf8_lossy(&p[3 + ml..3 + ml + rl]).into_owned();
    (message, code, reason)
}
