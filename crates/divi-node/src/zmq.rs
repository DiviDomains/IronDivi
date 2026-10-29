// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Divi Core's ZMQ notifications (zmq/*.cpp): `-zmqpubhashblock`,
//! `-zmqpubhashtx`, `-zmqpubrawblock` and `-zmqpubrawtx`, each a PUB socket
//! bound to the address given, speaking ZMTP 3.0 with the NULL mechanism.
//!
//! Every message has three frames: the topic, the body and the notifier's
//! sequence number, 4 bytes little-endian, counted from 0 at each start
//! (zmqpublishnotifier.cpp:129-145). Hashes are sent in the order they are
//! shown. Notifiers given the same address share one socket. Each
//! transaction is sent when it enters the mempool, when a block with it is
//! connected or disconnected, and when a connected block conflicts with it;
//! each new tip is sent once a chain operation ends, outside the initial
//! block download (zmqnotificationinterface.cpp:123-158, ChainTipManager.cpp,
//! ChainExtensionService.cpp:560-566).

use crate::mempool::Mempool;
use divi_primitives::block::Block;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::serialize;
use divi_primitives::transaction::Transaction;
use divi_storage::{BlockIndex, Chain, ChainEvent};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

/// The addresses of the four notifiers, as given
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZmqConfig {
    pub hashblock: Option<String>,
    pub hashtx: Option<String>,
    pub rawblock: Option<String>,
    pub rawtx: Option<String>,
}

impl ZmqConfig {
    /// The notifiers asked for, in Divi Core's order (ZMQNotifierFactory.cpp:4-8)
    fn wanted(&self) -> Vec<(Topic, &str)> {
        [
            (Topic::HashBlock, &self.hashblock),
            (Topic::HashTx, &self.hashtx),
            (Topic::RawBlock, &self.rawblock),
            (Topic::RawTx, &self.rawtx),
        ]
        .into_iter()
        .filter_map(|(t, a)| a.as_deref().map(|a| (t, a)))
        .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.wanted().is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Topic {
    HashBlock,
    HashTx,
    RawBlock,
    RawTx,
}

impl Topic {
    fn name(self) -> &'static str {
        match self {
            Topic::HashBlock => "hashblock",
            Topic::HashTx => "hashtx",
            Topic::RawBlock => "rawblock",
            Topic::RawTx => "rawtx",
        }
    }
}

/// How long a subscriber has for its greeting and READY
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Messages queued for one subscriber before more are dropped (libzmq's
/// default send high-water mark)
const QUEUE: usize = 1000;
/// The largest frame a subscriber may send (a subscription or a command)
const MAX_IN_FRAME: u64 = 64 * 1024;

/// Divi Core's IsInitialBlockDownload by the tip's time: more than 6 hours
/// old (ChainSyncHelpers.cpp:33-50); once false it stays false
const IBD_TIP_AGE: i64 = 6 * 60 * 60;

/// The ZMTP 3.0 greeting: signature, version 3.0, mechanism NULL, as-server 0
fn greeting() -> [u8; 64] {
    let mut g = [0u8; 64];
    g[0] = 0xff;
    g[9] = 0x7f;
    g[10] = 3;
    g[11] = 0;
    g[12..16].copy_from_slice(b"NULL");
    g
}

/// One frame; `more` when another frame of the message follows
fn encode_frame(out: &mut Vec<u8>, body: &[u8], more: bool, command: bool) {
    let flags = u8::from(more) | if command { 4 } else { 0 };
    if body.len() > 255 {
        out.push(flags | 2);
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    } else {
        out.push(flags);
        out.push(body.len() as u8);
    }
    out.extend_from_slice(body);
}

/// A command frame: its name, then its data
fn command(name: &str, data: &[u8]) -> Vec<u8> {
    let mut body = vec![name.len() as u8];
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);
    let mut out = Vec::new();
    encode_frame(&mut out, &body, false, true);
    out
}

/// READY with the socket type
fn ready() -> Vec<u8> {
    let mut props = vec![11u8];
    props.extend_from_slice(b"Socket-Type");
    props.extend_from_slice(&3u32.to_be_bytes());
    props.extend_from_slice(b"PUB");
    command("READY", &props)
}

/// A frame from a subscriber: (is a command, more follows, body)
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(bool, bool, Vec<u8>)> {
    let flags = r.read_u8().await?;
    let size = if flags & 2 != 0 {
        r.read_u64().await?
    } else {
        u64::from(r.read_u8().await?)
    };
    if size > MAX_IN_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; size as usize];
    r.read_exact(&mut body).await?;
    Ok((flags & 4 != 0, flags & 1 != 0, body))
}

struct Peer {
    id: u64,
    subscriptions: Arc<Mutex<Vec<Vec<u8>>>>,
    queue: mpsc::Sender<Arc<Vec<u8>>>,
}

/// One bound PUB socket and its subscribers
#[derive(Default)]
struct PubSocket {
    peers: Mutex<Vec<Peer>>,
    next_id: AtomicU64,
}

impl PubSocket {
    /// Queue `parts` as one message for every subscriber whose subscription
    /// is a prefix of the first part
    fn send(&self, parts: &[&[u8]]) {
        let mut message = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            encode_frame(&mut message, part, i + 1 < parts.len(), false);
        }
        let message = Arc::new(message);
        let topic = parts[0];
        self.peers.lock().retain(|peer| {
            let wanted = peer
                .subscriptions
                .lock()
                .iter()
                .any(|s| topic.starts_with(s));
            if !wanted {
                return true;
            }
            match peer.queue.try_send(message.clone()) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
    }

    /// Serve one subscriber until it goes
    async fn serve<S>(self: Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let handshake = async {
            wr.write_all(&greeting()).await?;
            let mut peer = [0u8; 64];
            rd.read_exact(&mut peer).await?;
            if peer[0] != 0xff || peer[9] != 0x7f || peer[10] < 3 || &peer[12..16] != b"NULL" {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not a ZMTP 3 NULL peer",
                ));
            }
            wr.write_all(&ready()).await?;
            let (is_command, _, _) = read_frame(&mut rd).await?;
            if !is_command {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no READY",
                ));
            }
            Ok::<(), std::io::Error>(())
        };
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
            Ok(Ok(())) => {}
            _ => return,
        }

        let (queue, mut outgoing) = mpsc::channel::<Arc<Vec<u8>>>(QUEUE);
        let subscriptions = Arc::new(Mutex::new(Vec::new()));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.peers.lock().push(Peer {
            id,
            subscriptions: subscriptions.clone(),
            queue: queue.clone(),
        });
        let writer = tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                if wr.write_all(&message).await.is_err() {
                    break;
                }
            }
        });
        // Subscriptions: a message of 1 and the prefix, or 0 and the prefix
        // to cancel (ZMTP 3.0); SUBSCRIBE and CANCEL commands (ZMTP 3.1)
        while let Ok((is_command, _, body)) = read_frame(&mut rd).await {
            if is_command {
                let Some(&len) = body.first() else { continue };
                let len = len as usize;
                if body.len() < 1 + len {
                    break;
                }
                let (name, data) = (&body[1..1 + len], &body[1 + len..]);
                match name {
                    b"SUBSCRIBE" => subscriptions.lock().push(data.to_vec()),
                    b"CANCEL" => remove_one(&subscriptions, data),
                    b"PING" => {
                        // PONG with the ping's context, after its 2-byte TTL
                        let context = data.get(2..).unwrap_or(&[]);
                        let _ = queue.try_send(Arc::new(command("PONG", context)));
                    }
                    _ => {}
                }
            } else {
                match body.split_first() {
                    Some((1, prefix)) => subscriptions.lock().push(prefix.to_vec()),
                    Some((0, prefix)) => remove_one(&subscriptions, prefix),
                    _ => {}
                }
            }
        }
        self.peers.lock().retain(|p| p.id != id);
        writer.abort();
    }
}

fn remove_one(subscriptions: &Mutex<Vec<Vec<u8>>>, prefix: &[u8]) {
    let mut subs = subscriptions.lock();
    if let Some(i) = subs.iter().position(|s| s == prefix) {
        subs.remove(i);
    }
}

/// A listening socket for an address libzmq would bind
enum Listener {
    Tcp(std::net::TcpListener),
    #[cfg(unix)]
    Ipc(std::os::unix::net::UnixListener),
}

/// Bind `address` as zmq_bind would: `tcp://<ip or *>:<port>` or, on
/// Unix, `ipc://<path>`
fn bind(address: &str) -> std::io::Result<Listener> {
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid argument");
    if let Some(rest) = address.strip_prefix("tcp://") {
        let (host, port) = rest.rsplit_once(':').ok_or_else(invalid)?;
        let port: u16 = if port == "*" {
            0
        } else {
            port.parse().map_err(|_| invalid())?
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let ip: std::net::IpAddr = if host == "*" {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            host.parse().map_err(|_| invalid())?
        };
        let listener = std::net::TcpListener::bind((ip, port))?;
        listener.set_nonblocking(true)?;
        return Ok(Listener::Tcp(listener));
    }
    #[cfg(unix)]
    if let Some(path) = address.strip_prefix("ipc://") {
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        return Ok(Listener::Ipc(listener));
    }
    Err(invalid())
}

fn accept_loop(listener: Listener, socket: Arc<PubSocket>) {
    match listener {
        Listener::Tcp(l) => {
            tokio::spawn(async move {
                let Ok(l) = tokio::net::TcpListener::from_std(l) else {
                    return;
                };
                while let Ok((stream, _)) = l.accept().await {
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(socket.clone().serve(stream));
                }
            });
        }
        #[cfg(unix)]
        Listener::Ipc(l) => {
            tokio::spawn(async move {
                let Ok(l) = tokio::net::UnixListener::from_std(l) else {
                    return;
                };
                while let Ok((stream, _)) = l.accept().await {
                    tokio::spawn(socket.clone().serve(stream));
                }
            });
        }
    }
}

struct Notifier {
    topic: Topic,
    socket: Arc<PubSocket>,
    sequence: AtomicU32,
}

/// The node's ZMQ notifications
pub struct ZmqNotifier {
    notifiers: Vec<Notifier>,
    chain: Weak<Chain>,
    mempool: Weak<Mempool>,
    /// The initial block download has ended (Core latches this)
    past_ibd: AtomicBool,
    /// Transactions of disconnected blocks already sent as back in the
    /// mempool: sent once, when Core's disconnectTip takes them back, not
    /// again when the mempool here does after the reorganization
    returned: Mutex<HashSet<Hash256>>,
}

impl ZmqNotifier {
    /// Bind every notifier asked for and start publishing; must run inside
    /// the tokio runtime. If one address cannot be bound, Divi Core logs it
    /// and runs without any notifier (zmqnotificationinterface.cpp:33-103),
    /// and so does this: None.
    pub fn start(
        config: &ZmqConfig,
        chain: &Arc<Chain>,
        mempool: &Arc<Mempool>,
    ) -> Option<Arc<ZmqNotifier>> {
        let wanted = config.wanted();
        if wanted.is_empty() {
            return None;
        }
        debug!(target: "zmq", "zmq: Initialize notification interface");
        let mut bound: Vec<(String, Arc<PubSocket>)> = Vec::new();
        let mut listeners = Vec::new();
        let mut notifiers = Vec::new();
        for (topic, address) in wanted {
            let socket = match bound.iter().find(|(a, _)| a == address) {
                Some((_, socket)) => {
                    debug!(target: "zmq", "zmq: Reusing socket for address {}", address);
                    socket.clone()
                }
                None => match bind(address) {
                    Ok(listener) => {
                        let socket = Arc::new(PubSocket::default());
                        bound.push((address.to_string(), socket.clone()));
                        listeners.push((listener, socket.clone()));
                        socket
                    }
                    Err(e) => {
                        debug!(target: "zmq", "zmq: Error: Failed to bind address, errno={}", e);
                        debug!(target: "zmq", "  Notifier {} failed (address = {})", topic.name(), address);
                        return None;
                    }
                },
            };
            debug!(target: "zmq", "  Notifier {} ready (address = {})", topic.name(), address);
            notifiers.push(Notifier {
                topic,
                socket,
                sequence: AtomicU32::new(0),
            });
        }
        for (listener, socket) in listeners {
            accept_loop(listener, socket);
        }

        let zmq = Arc::new(ZmqNotifier {
            notifiers,
            chain: Arc::downgrade(chain),
            mempool: Arc::downgrade(mempool),
            past_ibd: AtomicBool::new(false),
            returned: Mutex::new(HashSet::new()),
        });
        let z = Arc::downgrade(&zmq);
        mempool.add_added_listener(Arc::new(move |tx: &Transaction| {
            if let Some(z) = z.upgrade() {
                z.mempool_added(tx);
            }
        }));
        let z = Arc::downgrade(&zmq);
        chain.add_block_listener(Arc::new(move |event: &ChainEvent| {
            if let Some(z) = z.upgrade() {
                z.chain_event(event);
            }
        }));
        let z = Arc::downgrade(&zmq);
        chain.add_tip_listener(Arc::new(move |tip: &BlockIndex| {
            if let Some(z) = z.upgrade() {
                z.new_tip(tip);
            }
        }));
        // A new data directory: Core connects the genesis block after the
        // notifiers start, which sends its transaction (init.cpp:1495-1500)
        if chain.created_genesis() {
            if let Ok(Some(genesis)) = chain
                .get_block_index_by_height(0)
                .map(|i| i.and_then(|i| chain.get_block(&i.hash).ok().flatten()))
            {
                for tx in &genesis.transactions {
                    zmq.transaction(tx);
                }
            }
        }
        Some(zmq)
    }

    fn publish(&self, topic: Topic, body: &[u8]) {
        for n in self.notifiers.iter().filter(|n| n.topic == topic) {
            let sequence = n.sequence.fetch_add(1, Ordering::SeqCst);
            n.socket
                .send(&[topic.name().as_bytes(), body, &sequence.to_le_bytes()]);
        }
    }

    /// hashtx and rawtx, in the order the notifiers were set up
    fn transaction(&self, tx: &Transaction) {
        for n in &self.notifiers {
            match n.topic {
                Topic::HashTx => {
                    let mut hash = *tx.txid().as_bytes();
                    hash.reverse();
                    self.publish(Topic::HashTx, &hash);
                }
                Topic::RawTx => self.publish(Topic::RawTx, &serialize(tx)),
                _ => {}
            }
        }
    }

    /// hashblock and rawblock
    fn block(&self, hash: &Hash256, block: Option<&Block>) {
        for n in &self.notifiers {
            match n.topic {
                Topic::HashBlock => {
                    let mut bytes = *hash.as_bytes();
                    bytes.reverse();
                    self.publish(Topic::HashBlock, &bytes);
                }
                Topic::RawBlock => {
                    if let Some(block) = block {
                        self.publish(Topic::RawBlock, &serialize(block));
                    }
                }
                _ => {}
            }
        }
    }

    fn mempool_added(&self, tx: &Transaction) {
        if self.returned.lock().remove(&tx.txid()) {
            return;
        }
        self.transaction(tx);
    }

    fn chain_event(&self, event: &ChainEvent) {
        match event {
            // disconnectTip (ChainTipManager.cpp:155-190): first the
            // transactions AcceptToMemoryPool takes back, then every
            // transaction of the block. Taken back here: the block's
            // transactions other than its coinbase and coinstake, and those
            // spending one of them, which has just gone.
            ChainEvent::Disconnected(block) => {
                let rewards: HashSet<Hash256> = block
                    .transactions
                    .iter()
                    .filter(|tx| tx.is_coinbase() || tx.is_coinstake())
                    .map(|tx| tx.txid())
                    .collect();
                for tx in &block.transactions {
                    if rewards.contains(&tx.txid())
                        || tx.vin.iter().any(|i| rewards.contains(&i.prevout.txid))
                    {
                        continue;
                    }
                    self.returned.lock().insert(tx.txid());
                    self.transaction(tx);
                }
                for tx in &block.transactions {
                    self.transaction(tx);
                }
            }
            // connectTip (ChainTipManager.cpp:139-150): the mempool
            // transactions the block conflicts with, then the block's
            ChainEvent::Connected(block) => {
                if let Some(mempool) = self.mempool.upgrade() {
                    for tx in mempool.conflicts_with(&block.transactions) {
                        self.transaction(&tx);
                    }
                }
                for tx in &block.transactions {
                    self.returned.lock().remove(&tx.txid());
                    self.transaction(tx);
                }
            }
        }
    }

    fn new_tip(&self, tip: &BlockIndex) {
        let Some(chain) = self.chain.upgrade() else {
            return;
        };
        if self.initial_block_download(&chain, tip) {
            return;
        }
        let needs_block = self.notifiers.iter().any(|n| n.topic == Topic::RawBlock);
        let block = if needs_block {
            chain.get_block(&tip.hash).ok().flatten()
        } else {
            None
        };
        self.block(&tip.hash, block.as_ref());
    }

    fn initial_block_download(&self, chain: &Chain, tip: &BlockIndex) -> bool {
        if chain.is_importing() {
            return true;
        }
        if self.past_ibd.load(Ordering::SeqCst) {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if i64::from(tip.time) < now - IBD_TIP_AGE {
            return true;
        }
        self.past_ibd.store(true, Ordering::SeqCst);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_short_or_long_with_the_more_flag() {
        let mut out = Vec::new();
        encode_frame(&mut out, b"hashtx", true, false);
        assert_eq!(out, b"\x01\x06hashtx");
        let mut out = Vec::new();
        encode_frame(&mut out, &[7u8; 300], false, false);
        assert_eq!(&out[..9], &[2, 0, 0, 0, 0, 0, 0, 1, 44]);
        assert_eq!(out.len(), 9 + 300);
    }

    #[test]
    fn addresses_bind_as_libzmq_takes_them() {
        assert!(matches!(bind("tcp://127.0.0.1:*"), Ok(Listener::Tcp(_))));
        assert!(matches!(bind("tcp://*:*"), Ok(Listener::Tcp(_))));
        for bad in [
            "notanaddress",
            "tcp://127.0.0.1",
            "tcp://localhost:28332",
            "udp://1.2.3.4:5",
        ] {
            assert!(bind(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn notifiers_are_in_cores_order() {
        let config = ZmqConfig {
            rawtx: Some("a".into()),
            hashblock: Some("b".into()),
            ..Default::default()
        };
        assert_eq!(
            config.wanted(),
            vec![(Topic::HashBlock, "b"), (Topic::RawTx, "a")]
        );
    }
}
