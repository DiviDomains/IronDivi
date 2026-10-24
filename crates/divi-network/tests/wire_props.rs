// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Properties of the peer message decoders: every message the node sends or
//! reads survives an encode/decode round trip, fixed vectors match Divi
//! Core's encoding, random and damaged bytes never panic, and each size
//! limit and its edge behave as in Divi Core 3.0.0.
//!
//! Core references are to Divi Core 3.0.0 (9e2f76c), `divi/src/`.

use bytes::BytesMut;
use divi_network::codec::Decoded;
use divi_network::constants::{
    MAINNET_MAGIC, MAX_HEADERS_RESULTS, MAX_INV_SIZE, MAX_MESSAGE_SIZE, REGTEST_MAGIC,
};
use divi_network::version::MAX_SUBVERSION_LENGTH;
use divi_network::{
    DiviCodec, GetBlocksMessage, InvItem, InvType, MessageHeader, NetAddr, NetworkError,
    NetworkMessage, RejectMessage, SporkMessage, VersionMessage, COMMAND_SIZE, HEADER_SIZE,
};
use divi_primitives::amount::Amount;
use divi_primitives::block::{Block, BlockHeader};
use divi_primitives::compact::{CompactSize, MAX_SIZE};
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::{serialize, Encodable};
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use proptest::prelude::*;
use tokio_util::codec::Decoder;

/// Every command `NetworkMessage::deserialize` knows
const COMMANDS: &[&str] = &[
    "version",
    "verack",
    "addr",
    "getaddr",
    "inv",
    "getdata",
    "notfound",
    "getblocks",
    "getheaders",
    "headers",
    "block",
    "tx",
    "ping",
    "pong",
    "mempool",
    "reject",
    "alert",
    "filterload",
    "filteradd",
    "filterclear",
    "sendheaders",
    "sporkcount",
    "getsporks",
    "spork",
    "ssc",
    "govsync",
    "dseg",
    "mnb",
    "mnp",
    "mnw",
];

fn compact(n: u64) -> Vec<u8> {
    let mut v = Vec::new();
    CompactSize(n).encode(&mut v).unwrap();
    v
}

fn frame(magic: [u8; 4], command: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = MessageHeader::new(magic, command, payload).serialize();
    v.extend_from_slice(payload);
    v
}

/// Run the frame decoder over `bytes` fed in chunks of `chunk` bytes;
/// return what it produced and whether it ended the stream with an error
fn decode_stream(bytes: &[u8], chunk: usize) -> (Vec<Decoded>, Option<NetworkError>) {
    let mut codec = DiviCodec::new(MAINNET_MAGIC);
    let mut buf = BytesMut::new();
    let mut out = Vec::new();
    for piece in bytes.chunks(chunk.max(1)) {
        buf.extend_from_slice(piece);
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(item)) => out.push(item),
                Ok(None) => break,
                Err(e) => return (out, Some(e)),
            }
        }
    }
    (out, None)
}

/// Decode one framed message and require it to parse
fn decode_one(bytes: &[u8]) -> NetworkMessage {
    let (mut items, err) = decode_stream(bytes, bytes.len());
    assert!(err.is_none(), "frame refused: {:?}", err);
    assert_eq!(items.len(), 1);
    match items.pop().unwrap() {
        Decoded::Message(m) => m,
        Decoded::Malformed { command, error } => panic!("{} did not parse: {}", command, error),
    }
}

/// Encode, frame, decode: the result is the same message (same fields,
/// same bytes when encoded again)
fn assert_round_trip(msg: &NetworkMessage) {
    let bytes = msg.to_bytes(MAINNET_MAGIC).unwrap();
    let back = decode_one(&bytes);
    assert_eq!(back.command(), msg.command());
    assert_eq!(format!("{:?}", back), format!("{:?}", msg));
    assert_eq!(back.to_bytes(MAINNET_MAGIC).unwrap(), bytes);
}

// ------------------------------------------------------------------
// Strategies
// ------------------------------------------------------------------

fn hash() -> impl Strategy<Value = Hash256> {
    any::<[u8; 32]>().prop_map(Hash256::from_bytes)
}

fn net_addr() -> impl Strategy<Value = NetAddr> {
    (any::<u64>(), any::<[u8; 16]>(), any::<u16>())
        .prop_map(|(services, ip, port)| NetAddr::from_ipv6(ip, port, services))
}

fn known_inv_type() -> impl Strategy<Value = InvType> {
    (1u32..=15).prop_map(|t| InvType::from_u32(t).unwrap())
}

fn inv_item() -> impl Strategy<Value = InvItem> {
    (known_inv_type(), hash()).prop_map(|(t, h)| InvItem::new(t, h))
}

fn ascii(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(0x20u8..0x7f, 0..=max).prop_map(|v| String::from_utf8(v).unwrap())
}

fn version_message() -> impl Strategy<Value = VersionMessage> {
    (
        (
            any::<i32>(),
            any::<u64>(),
            any::<i64>(),
            net_addr(),
            net_addr(),
        ),
        (
            any::<u64>(),
            ascii(MAX_SUBVERSION_LENGTH),
            any::<i32>(),
            any::<bool>(),
        ),
    )
        .prop_map(
            |((version, services, timestamp, addr_recv, addr_from), (nonce, ua, h, relay))| {
                VersionMessage {
                    version,
                    services,
                    timestamp,
                    addr_recv,
                    addr_from,
                    nonce,
                    user_agent: ua,
                    start_height: h,
                    relay,
                }
            },
        )
}

fn block_header() -> impl Strategy<Value = BlockHeader> {
    (
        any::<i32>(),
        hash(),
        hash(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        hash(),
    )
        .prop_map(
            |(version, prev, merkle, time, bits, nonce, acc)| BlockHeader {
                version,
                prev_block: prev,
                merkle_root: merkle,
                time,
                bits,
                nonce,
                // Only serialized for version > 3
                accumulator_checkpoint: if version > 3 { acc } else { Hash256::zero() },
            },
        )
}

fn script(max: usize) -> impl Strategy<Value = Script> {
    proptest::collection::vec(any::<u8>(), 0..=max).prop_map(Script::from_bytes)
}

fn transaction() -> impl Strategy<Value = Transaction> {
    let txin = (hash(), any::<u32>(), script(80), any::<u32>())
        .prop_map(|(h, n, s, seq)| TxIn::new(OutPoint::new(h, n), s, seq));
    let txout = (any::<i64>(), script(40)).prop_map(|(v, s)| TxOut::new(Amount::from_sat(v), s));
    (
        any::<i32>(),
        proptest::collection::vec(txin, 0..4),
        proptest::collection::vec(txout, 0..4),
        any::<u32>(),
    )
        .prop_map(|(version, vin, vout, lock_time)| Transaction {
            version,
            vin,
            vout,
            lock_time,
        })
}

fn block() -> impl Strategy<Value = Block> {
    (
        block_header(),
        proptest::collection::vec(transaction(), 0..4),
        proptest::collection::vec(any::<u8>(), 0..80),
        any::<bool>(),
    )
        .prop_map(|(header, mut transactions, sig, stake)| {
            // Make the second transaction a coinstake (an input that is not
            // a coinbase, an empty first output) so the signature is used
            if stake && transactions.len() > 1 {
                let cs = &mut transactions[1];
                cs.vin.push(TxIn::new(
                    OutPoint::new(Hash256::from_bytes([1; 32]), 0),
                    Script::default(),
                    0,
                ));
                cs.vin.rotate_right(1);
                cs.vout.insert(0, TxOut::empty());
                cs.vout
                    .push(TxOut::new(Amount::from_sat(1), Script::default()));
            }
            let mut b = Block {
                header,
                transactions,
                block_sig: Vec::new(),
            };
            // The signature is on the wire only for a proof-of-stake block
            // (Core primitives/block.h:112)
            if b.is_proof_of_stake() {
                b.block_sig = sig;
            }
            b
        })
}

fn alert_payload() -> impl Strategy<Value = Vec<u8>> {
    (
        proptest::collection::vec(any::<u8>(), 0..200),
        proptest::collection::vec(any::<u8>(), 0..80),
    )
        .prop_map(|(msg, sig)| {
            let mut v = compact(msg.len() as u64);
            v.extend_from_slice(&msg);
            v.extend(compact(sig.len() as u64));
            v.extend_from_slice(&sig);
            v
        })
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=max)
}

/// Every message the node sends or reads
fn network_message() -> impl Strategy<Value = NetworkMessage> {
    prop_oneof![
        version_message().prop_map(NetworkMessage::Version),
        Just(NetworkMessage::Verack),
        proptest::collection::vec((any::<u32>(), net_addr()), 0..20).prop_map(NetworkMessage::Addr),
        Just(NetworkMessage::GetAddr),
        proptest::collection::vec(inv_item(), 0..20).prop_map(NetworkMessage::Inv),
        proptest::collection::vec(inv_item(), 0..20).prop_map(NetworkMessage::GetData),
        proptest::collection::vec(inv_item(), 0..20).prop_map(NetworkMessage::NotFound),
        (
            any::<i32>(),
            proptest::collection::vec(hash(), 0..20),
            hash()
        )
            .prop_map(|(v, l, s)| {
                NetworkMessage::GetBlocks(GetBlocksMessage {
                    version: v,
                    locator_hashes: l,
                    stop_hash: s,
                })
            }),
        (
            any::<i32>(),
            proptest::collection::vec(hash(), 0..20),
            hash()
        )
            .prop_map(|(v, l, s)| {
                NetworkMessage::GetHeaders(GetBlocksMessage {
                    version: v,
                    locator_hashes: l,
                    stop_hash: s,
                })
            }),
        proptest::collection::vec(block_header(), 0..10).prop_map(NetworkMessage::Headers),
        block().prop_map(NetworkMessage::Block),
        transaction().prop_map(NetworkMessage::Tx),
        any::<u64>().prop_map(NetworkMessage::Ping),
        any::<u64>().prop_map(NetworkMessage::Pong),
        Just(NetworkMessage::Mempool),
        (ascii(COMMAND_SIZE), any::<u8>(), ascii(111), bytes(32)).prop_map(|(m, c, r, d)| {
            NetworkMessage::Reject(RejectMessage {
                message: m,
                code: c,
                reason: r,
                data: d,
            })
        }),
        alert_payload().prop_map(NetworkMessage::Alert),
        bytes(64).prop_map(NetworkMessage::FilterLoad),
        bytes(64).prop_map(NetworkMessage::FilterAdd),
        Just(NetworkMessage::FilterClear),
        Just(NetworkMessage::SendHeaders),
        any::<u32>().prop_map(NetworkMessage::SporkCount),
        Just(NetworkMessage::GetSporks),
        (any::<i32>(), "\\PC{0,40}", any::<i64>(), bytes(72)).prop_map(|(id, v, t, sig)| {
            NetworkMessage::Spork(SporkMessage {
                spork_id: id,
                value: v,
                time_signed: t,
                signature: sig,
            })
        }),
        (any::<i32>(), any::<i32>())
            .prop_map(|(item_id, count)| NetworkMessage::SyncStatusCount { item_id, count }),
        Just(NetworkMessage::GetSyncStatus),
        bytes(64).prop_map(NetworkMessage::RequestMasternodeList),
        bytes(64).prop_map(NetworkMessage::MasternodeBroadcast),
        bytes(64).prop_map(NetworkMessage::MasternodePing),
        bytes(64).prop_map(NetworkMessage::MasternodeWinner),
        ("[a-z]{1,12}", bytes(64))
            .prop_filter("not a known command", |(c, _)| !COMMANDS
                .contains(&c.as_str()))
            .prop_map(|(c, p)| NetworkMessage::Unknown(c, p)),
    ]
}

/// A valid message's encoding with a few bytes changed, inserted, removed
/// or cut off
fn damaged(bytes: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec((0u8..4, any::<prop::sample::Index>(), any::<u8>()), 1..6).prop_map(
        move |edits| {
            let mut b = bytes.clone();
            for (kind, at, byte) in edits {
                if b.is_empty() {
                    b.push(byte);
                    continue;
                }
                let i = at.index(b.len());
                match kind {
                    0 => b[i] ^= byte | 1,
                    1 => b.insert(i, byte),
                    2 => {
                        b.remove(i);
                    }
                    _ => b.truncate(i),
                }
            }
            b
        },
    )
}

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ------------------------------------------------------------------
// 1. Round trips
// ------------------------------------------------------------------

proptest! {
    #![proptest_config(config(512))]

    #[test]
    fn every_message_round_trips(msg in network_message()) {
        assert_round_trip(&msg);
    }

    /// Inventory, address and locator lists split across reads decode the same
    #[test]
    fn frames_decode_the_same_in_any_chunking(
        msgs in proptest::collection::vec(network_message(), 1..5),
        chunk in 1usize..64,
    ) {
        let mut stream = Vec::new();
        for m in &msgs {
            stream.extend(m.to_bytes(MAINNET_MAGIC).unwrap());
        }
        let (items, err) = decode_stream(&stream, chunk);
        prop_assert!(err.is_none());
        prop_assert_eq!(items.len(), msgs.len());
        for (item, m) in items.iter().zip(&msgs) {
            match item {
                Decoded::Message(back) => prop_assert_eq!(format!("{:?}", back), format!("{:?}", m)),
                Decoded::Malformed { command, error } => {
                    return Err(TestCaseError::fail(format!("{}: {}", command, error)))
                }
            }
        }
    }

    #[test]
    fn compact_size_round_trips_up_to_max_size(n in 0u64..=MAX_SIZE) {
        let enc = compact(n);
        let mut r = &enc[..];
        let back = <CompactSize as divi_primitives::serialize::Decodable>::decode(&mut r).unwrap();
        prop_assert_eq!(back.value(), n);
        prop_assert!(r.is_empty());
    }
}

// ------------------------------------------------------------------
// Fixed vectors, built from Divi Core's serialization by hand
// ------------------------------------------------------------------

/// `CMessageHeader` (protocol.h:43-46): start, command padded with zeros,
/// size, first 4 bytes of the double SHA-256 of the payload. The checksum
/// of an empty payload is 5df6e0e2 (sha256d("") = 5df6e0e2761359d3...).
#[test]
fn vector_verack_frame() {
    let bytes = NetworkMessage::Verack.to_bytes(MAINNET_MAGIC).unwrap();
    assert_eq!(
        hex::encode(bytes),
        concat!(
            "dfa08d8f",                 // mainnet pchMessageStart, chainparams.cpp
            "76657261636b000000000000", // "verack"
            "00000000",
            "5df6e0e2",
        )
    );
}

/// `ping` carries a little-endian uint64 nonce (main.cpp:510)
#[test]
fn vector_ping_and_pong() {
    let p = NetworkMessage::Ping(0x0102030405060708)
        .serialize_payload()
        .unwrap();
    assert_eq!(hex::encode(&p), "0807060504030201");
    let f = NetworkMessage::Pong(0x0102030405060708)
        .to_bytes(REGTEST_MAGIC)
        .unwrap();
    assert_eq!(&f[..4], &[0xa1, 0xcf, 0x7e, 0xac]);
    assert_eq!(&f[4..16], b"pong\0\0\0\0\0\0\0\0");
    assert_eq!(&f[16..20], &[8, 0, 0, 0]);
    assert_eq!(&f[24..], &p[..]);
}

/// `CInv` (protocol.h:158-159): int type, uint256 hash
#[test]
fn vector_inv() {
    let h = Hash256::from_bytes([0x11; 32]);
    let p = NetworkMessage::Inv(vec![InvItem::new(InvType::Block, h)])
        .serialize_payload()
        .unwrap();
    assert_eq!(hex::encode(&p), format!("0102000000{}", "11".repeat(32)));
}

/// `CAddress` in an `addr` message (protocol.h:106-111): time, services,
/// IPv6 address, port in network byte order
#[test]
fn vector_addr() {
    let a = NetAddr::from_ipv4([127, 0, 0, 1], 51472, 1);
    let p = NetworkMessage::Addr(vec![(0x5f5e1000, a)])
        .serialize_payload()
        .unwrap();
    assert_eq!(
        hex::encode(&p),
        concat!(
            "01",
            "00105e5f",
            "0100000000000000",
            "00000000000000000000ffff7f000001",
            "c910",
        )
    );
}

/// The version message as Divi Core sends it (Node.cpp:1004-1005):
/// version, services, time, addrYou, addrMe (no time field), nonce,
/// subversion, height, relay
#[test]
fn vector_version() {
    let v = VersionMessage {
        version: 70920,
        services: 1,
        timestamp: 0x6000_0000,
        addr_recv: NetAddr::from_ipv4([10, 0, 0, 1], 51472, 0),
        addr_from: NetAddr::from_ipv4([0, 0, 0, 0], 0, 1),
        nonce: 0x0807_0605_0403_0201,
        user_agent: "/Divi:3.0.0/".into(),
        start_height: 100,
        relay: true,
    };
    let expected = concat!(
        "08150100",
        "0100000000000000",
        "0000006000000000",
        "0000000000000000",
        "00000000000000000000ffff0a000001",
        "c910",
        "0100000000000000",
        "00000000000000000000ffff00000000",
        "0000",
        "0102030405060708",
        "0c2f446976693a332e302e302f",
        "64000000",
        "01",
    );
    assert_eq!(hex::encode(v.serialize()), expected);
    assert_eq!(
        VersionMessage::deserialize(&hex::decode(expected).unwrap()).unwrap(),
        v
    );
}

/// `getblocks`: `CBlockLocator` (nVersion, vHave) then hashStop (main.cpp:628)
#[test]
fn vector_getblocks() {
    let m = GetBlocksMessage {
        version: 70920,
        locator_hashes: vec![Hash256::from_bytes([0xaa; 32])],
        stop_hash: Hash256::zero(),
    };
    assert_eq!(
        hex::encode(m.serialize()),
        format!("0815010001{}{}", "aa".repeat(32), "00".repeat(32))
    );
}

/// `CSporkMessage` (spork.h:83-87): id, value, time, signature
#[test]
fn vector_spork() {
    let s = SporkMessage {
        spork_id: 10013,
        value: "[1]".into(),
        time_signed: 1_600_000_000,
        signature: vec![0xde, 0xad],
    };
    assert_eq!(
        hex::encode(s.serialize()),
        "1d270000035b315d00105e5f0000000002dead"
    );
}

/// `ssc` is two ints (masternode-sync.cpp:102, 192)
#[test]
fn vector_ssc() {
    let p = NetworkMessage::SyncStatusCount {
        item_id: 4,
        count: 250,
    }
    .serialize_payload()
    .unwrap();
    assert_eq!(hex::encode(p), "04000000fa000000");
}

/// `reject` as Divi Core sends it for a payload that does not parse
/// (main.cpp:1054): command, code, reason
#[test]
fn vector_reject() {
    let r = RejectMessage {
        message: "tx".into(),
        code: 1,
        reason: "error parsing message".into(),
        data: vec![],
    };
    let mut expected = vec![2u8];
    expected.extend_from_slice(b"tx");
    expected.push(1);
    expected.push(21);
    expected.extend_from_slice(b"error parsing message");
    assert_eq!(r.serialize(), expected);
}

/// Divi mainnet genesis (chainparams.cpp:208-228): the coinbase as Core
/// builds it hashes to Core's merkle root and the header to Core's genesis
/// hash; the same bytes decode as `tx`, `block` and `headers`
#[test]
fn vector_mainnet_genesis() {
    let stamp: &[u8] =
        b"September 26, 2018 - US-Iran: Trump set to chair key UN Security Council session";
    // CScript() << 486604799 << CScriptNum(4) << stamp
    let mut sig = vec![0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04];
    if stamp.len() < 0x4c {
        sig.push(stamp.len() as u8);
    } else {
        sig.extend_from_slice(&[0x4c, stamp.len() as u8]);
    }
    sig.extend_from_slice(stamp);
    let mut spk = vec![0x41];
    spk.extend(
        hex::decode(divi_primitives::test_vectors::genesis::mainnet::COINBASE_PUBKEY).unwrap(),
    );
    spk.push(0xac);
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::null(),
            Script::from_bytes(sig),
            0xffff_ffff,
        )],
        vout: vec![TxOut::new(Amount::from_divi(50), Script::from_bytes(spk))],
        lock_time: 0,
    };
    assert_eq!(
        coinbase.txid().to_hex(),
        "ec803cc6b5e68728ec0117cb1154b6d2893152f89d61319647db106908888bd6"
    );
    let header = BlockHeader {
        version: 1,
        prev_block: Hash256::zero(),
        merkle_root: coinbase.txid(),
        time: 1537971708,
        bits: 0x1e0ffff0,
        nonce: 749845,
        accumulator_checkpoint: Hash256::zero(),
    };
    assert_eq!(serialize(&header).len(), 80);
    assert_eq!(
        divi_crypto::compute_block_hash(&header).to_hex(),
        "00000e258596876664989374c7ee36445cf5f4f80889af415cc32478214394ea"
    );

    let tx_bytes = serialize(&coinbase);
    match decode_one(&frame(MAINNET_MAGIC, "tx", &tx_bytes)) {
        NetworkMessage::Tx(t) => assert_eq!(t, coinbase),
        other => panic!("{:?}", other),
    }
    let block = Block {
        header: header.clone(),
        transactions: vec![coinbase],
        block_sig: vec![],
    };
    let block_bytes = serialize(&block);
    assert_eq!(&block_bytes[..80], &serialize(&header)[..]);
    assert_eq!(&block_bytes[80..81], &[1]);
    match decode_one(&frame(MAINNET_MAGIC, "block", &block_bytes)) {
        NetworkMessage::Block(b) => assert_eq!(b, block),
        other => panic!("{:?}", other),
    }
    // A headers entry is the header and a zero transaction count
    let mut hp = vec![1u8];
    hp.extend(serialize(&header));
    hp.push(0);
    assert_eq!(
        NetworkMessage::Headers(vec![header.clone()])
            .serialize_payload()
            .unwrap(),
        hp
    );
    match decode_one(&frame(MAINNET_MAGIC, "headers", &hp)) {
        NetworkMessage::Headers(h) => assert_eq!(h, vec![header]),
        other => panic!("{:?}", other),
    }
}

/// `WriteCompactSize` (serialize.h): one byte below 253, then fd/fe/ff
/// with 2, 4 or 8 little-endian bytes
#[test]
fn vector_compact_size() {
    for (n, hex) in [
        (0u64, "00"),
        (252, "fc"),
        (253, "fdfd00"),
        (0xffff, "fdffff"),
        (0x10000, "fe00000100"),
        (MAX_SIZE, "fe00000002"),
    ] {
        assert_eq!(hex::encode(compact(n)), hex, "{}", n);
    }
}

// ------------------------------------------------------------------
// 2. Random and damaged bytes: no panic, refusal is an error
// ------------------------------------------------------------------

proptest! {
    #![proptest_config(config(1024))]

    #[test]
    fn random_payloads_never_panic(cmd in prop::sample::select(COMMANDS), payload in bytes(600)) {
        let _ = NetworkMessage::deserialize(cmd, &payload);
    }

    #[test]
    fn random_streams_never_panic(stream in bytes(600), chunk in 1usize..100) {
        let _ = decode_stream(&stream, chunk);
    }

    /// A stream that starts with the right magic and a sane size, so the
    /// random rest reaches the payload decoders through the frame decoder
    #[test]
    fn random_frames_never_panic(
        cmd in prop::sample::select(COMMANDS),
        payload in bytes(600),
        chunk in 1usize..100,
    ) {
        let _ = decode_stream(&frame(MAINNET_MAGIC, cmd, &payload), chunk);
    }
}

proptest! {
    #![proptest_config(config(1024))]

    #[test]
    fn damaged_messages_never_panic(
        (cmd, payload) in network_message().prop_flat_map(|m| {
            let cmd = m.command().to_string();
            (Just(cmd), damaged(m.serialize_payload().unwrap()))
        }),
    ) {
        let _ = NetworkMessage::deserialize(&cmd, &payload);
        let _ = decode_stream(&frame(MAINNET_MAGIC, &cmd, &payload), payload.len().max(1));
    }

    #[test]
    fn damaged_frames_never_panic(
        stream in network_message().prop_flat_map(|m| damaged(m.to_bytes(MAINNET_MAGIC).unwrap())),
        chunk in 1usize..64,
    ) {
        let _ = decode_stream(&stream, chunk);
    }

    /// A payload cut short is a parse error ("end of data"), never a
    /// message read from missing bytes
    #[test]
    fn truncated_payloads_are_refused(
        (m, cut) in network_message()
            .prop_filter("has a payload that must be complete", |m| !matches!(m,
                NetworkMessage::Reject(_) | NetworkMessage::Version(_) | NetworkMessage::Unknown(..)
                | NetworkMessage::FilterLoad(_) | NetworkMessage::FilterAdd(_)
                | NetworkMessage::RequestMasternodeList(_) | NetworkMessage::MasternodeBroadcast(_)
                | NetworkMessage::MasternodePing(_) | NetworkMessage::MasternodeWinner(_))
                && !m.serialize_payload().unwrap().is_empty())
            .prop_flat_map(|m| {
                let len = m.serialize_payload().unwrap().len();
                (Just(m), 0..len.max(1))
            }),
    ) {
        let p = m.serialize_payload().unwrap();
        prop_assert!(NetworkMessage::deserialize(m.command(), &p[..cut]).is_err());
    }

    /// A count above `MAX_SIZE` is refused before anything is read for it
    /// (serialize.h:453), whatever follows
    #[test]
    fn counts_above_max_size_are_refused(
        cmd in prop::sample::select(&["addr", "inv", "getdata", "notfound", "headers", "alert", "reject", "block", "tx"][..]),
        n in (MAX_SIZE + 1)..=u64::MAX,
        rest in bytes(64),
    ) {
        let mut p = Vec::new();
        match cmd {
            // Block: the header comes before the transaction count
            "block" => p.extend(serialize(&BlockHeader { version: 4, ..Default::default() })),
            // Transaction: version before the input count
            "tx" => p.extend_from_slice(&1i32.to_le_bytes()),
            _ => {}
        }
        p.extend(compact(n));
        p.extend(rest);
        let e = NetworkMessage::deserialize(cmd, &p).unwrap_err();
        prop_assert!(e.to_string().contains("size too large"), "{}", e);
    }

    /// A size written in more bytes than it needs is refused, as Core's
    /// `ReadCompactSize` does ("non-canonical", serialize.h:432-447)
    #[test]
    fn non_canonical_sizes_are_refused(n in 0u64..0x1_0000_0000) {
        let mut forms = Vec::new();
        if n < 253 {
            let mut v = vec![0xfd];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            forms.push(v);
        }
        if n <= 0xffff {
            let mut v = vec![0xfe];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            forms.push(v);
        }
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        forms.push(v);
        for f in forms {
            let mut r = &f[..];
            prop_assert!(<CompactSize as divi_primitives::serialize::Decodable>::decode(&mut r).is_err());
            prop_assert!(NetworkMessage::deserialize("inv", &f).is_err());
        }
    }
}

// ------------------------------------------------------------------
// 3. Limits and their edges
// ------------------------------------------------------------------

/// The values are Divi Core's
#[test]
fn limits_are_cores() {
    // Node.cpp:118 MAX_PROTOCOL_MESSAGE_LENGTH
    assert_eq!(MAX_MESSAGE_SIZE, 2 * 1024 * 1024);
    // serialize.h:34 MAX_SIZE
    assert_eq!(MAX_SIZE, 0x0200_0000);
    // Node.h:27 MAX_INV_SZ
    assert_eq!(MAX_INV_SIZE, 50_000);
    // defaultValues.h:85 MAX_HEADERS_RESULTS
    assert_eq!(MAX_HEADERS_RESULTS, 2000);
    // main.cpp:383 LIMITED_STRING(strSubVer, 256)
    assert_eq!(MAX_SUBVERSION_LENGTH, 256);
    // protocol.h CMessageHeader: COMMAND_SIZE 12, HEADER_SIZE 24
    assert_eq!(COMMAND_SIZE, 12);
    assert_eq!(HEADER_SIZE, 24);
    // main.cpp:946 LIMITED_STRING(strMsg, COMMAND_SIZE),
    // defaultValues.h:94 MAX_REJECT_MESSAGE_LENGTH
    // (checked against the decoder in `reject_edges`)
}

fn header_claiming(size: u32) -> Vec<u8> {
    let mut h = MessageHeader::new(MAINNET_MAGIC, "block", &[]).serialize();
    h[16..20].copy_from_slice(&size.to_le_bytes());
    h
}

/// A payload of exactly 2 MiB is waited for; one byte more ends the
/// connection, decided from the header alone (Node.cpp:132-135)
#[test]
fn frame_size_edge() {
    let mut codec = DiviCodec::new(MAINNET_MAGIC);
    let mut buf = BytesMut::from(&header_claiming(MAX_MESSAGE_SIZE)[..]);
    assert!(codec.decode(&mut buf).unwrap().is_none());

    for size in [
        MAX_MESSAGE_SIZE + 1,
        MAX_SIZE as u32,
        MAX_SIZE as u32 + 1,
        u32::MAX,
    ] {
        let mut codec = DiviCodec::new(MAINNET_MAGIC);
        let mut buf = BytesMut::from(&header_claiming(size)[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(NetworkError::MessageTooLarge { .. })
        ));
    }
}

/// A full 2 MiB message decodes
#[test]
fn frame_of_exactly_the_limit_decodes() {
    let payload = vec![0u8; MAX_MESSAGE_SIZE as usize];
    match decode_one(&frame(MAINNET_MAGIC, "filterload", &payload)) {
        NetworkMessage::FilterLoad(p) => assert_eq!(p.len(), payload.len()),
        other => panic!("{:?}", other),
    }
}

/// A header waiting for a large payload does not reserve the whole payload
/// before it arrives: Divi Core grows its buffer at most 256 KiB ahead of
/// the bytes received (Node.cpp:80-84)
#[test]
fn header_alone_does_not_reserve_the_whole_payload() {
    let mut codec = DiviCodec::new(MAINNET_MAGIC);
    let mut buf = BytesMut::from(&header_claiming(MAX_MESSAGE_SIZE)[..]);
    assert!(codec.decode(&mut buf).unwrap().is_none());
    assert!(
        buf.capacity() <= 2 * (256 * 1024 + HEADER_SIZE),
        "reserved {} bytes for a payload not yet sent",
        buf.capacity()
    );
    // The payload still decodes when it arrives in pieces
    let payload = vec![7u8; MAX_MESSAGE_SIZE as usize];
    let mut full = MessageHeader::new(MAINNET_MAGIC, "filterload", &payload).serialize();
    full.extend_from_slice(&payload);
    let (items, err) = decode_stream(&full, 100_000);
    assert!(err.is_none());
    assert!(
        matches!(&items[..], [Decoded::Message(NetworkMessage::FilterLoad(p))] if p.len() == payload.len())
    );
}

/// Wrong magic ends the stream; a bad checksum or a bad command skips only
/// that message (main.cpp:984-1010)
#[test]
fn header_checks() {
    let good = NetworkMessage::Ping(5).to_bytes(MAINNET_MAGIC).unwrap();

    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 1;
    assert!(matches!(
        decode_stream(&wrong_magic, 7).1,
        Some(NetworkError::InvalidMagic)
    ));

    let mut bad_sum = good.clone();
    bad_sum[23] ^= 1;
    bad_sum.extend_from_slice(&good);
    let (items, err) = decode_stream(&bad_sum, 5);
    assert!(err.is_none());
    assert!(matches!(
        &items[..],
        [Decoded::Message(NetworkMessage::Ping(5))]
    ));

    for bad_cmd in [
        b"pi\0g\0\0\0\0\0\0\0\0",
        b"pi\x01g\0\0\0\0\0\0\0\0",
        b"pi\x7fg\0\0\0\0\0\0\0\0",
    ] {
        let mut b = good.clone();
        b[4..16].copy_from_slice(bad_cmd);
        b.extend_from_slice(&good);
        let (items, err) = decode_stream(&b, 3);
        assert!(err.is_none());
        assert!(matches!(
            &items[..],
            [Decoded::Message(NetworkMessage::Ping(5))]
        ));
    }
}

/// A count of `MAX_SIZE` passes the size check and then fails for want of
/// data; `MAX_SIZE + 1` fails the size check (serialize.h:453)
#[test]
fn compact_size_edge() {
    let at = NetworkMessage::deserialize("inv", &compact(MAX_SIZE)).unwrap_err();
    assert!(at.to_string().contains("end of data"), "{}", at);
    let over = NetworkMessage::deserialize("inv", &[0xfe, 0x01, 0x00, 0x00, 0x02]).unwrap_err();
    assert!(over.to_string().contains("size too large"), "{}", over);
}

fn inv_payload(n: usize) -> Vec<u8> {
    let mut p = compact(n as u64);
    for i in 0..n {
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&(i as u64).to_le_bytes());
        p.extend_from_slice(&[0; 24]);
    }
    p
}

/// Core reads the whole inventory and then refuses more than `MAX_INV_SZ`
/// items with a misbehaviour score of 20 (main.cpp:563, 617); the decoder
/// hands both sides of the edge to the handler, which applies the limit
#[test]
fn inventory_edge_reaches_the_handler() {
    for cmd in ["inv", "getdata"] {
        for n in [MAX_INV_SIZE, MAX_INV_SIZE + 1] {
            let p = inv_payload(n);
            assert!(p.len() <= MAX_MESSAGE_SIZE as usize);
            match NetworkMessage::deserialize(cmd, &p).unwrap() {
                NetworkMessage::Inv(v) | NetworkMessage::GetData(v) => assert_eq!(v.len(), n),
                other => panic!("{:?}", other),
            }
        }
    }
}

/// The same for `addr` and its 1000 limit (main.cpp:529)
#[test]
fn addr_edge_reaches_the_handler() {
    for n in [1000usize, 1001] {
        let addrs: Vec<_> = (0..n)
            .map(|i| (i as u32, NetAddr::from_ipv4([10, 0, 0, 1], i as u16, 1)))
            .collect();
        let p = NetworkMessage::Addr(addrs).serialize_payload().unwrap();
        match NetworkMessage::deserialize("addr", &p).unwrap() {
            NetworkMessage::Addr(v) => assert_eq!(v.len(), n),
            other => panic!("{:?}", other),
        }
    }
}

fn headers_payload(n: usize) -> Vec<u8> {
    let mut p = compact(n as u64);
    for i in 0..n {
        p.extend(serialize(&BlockHeader {
            version: 4,
            nonce: i as u32,
            ..Default::default()
        }));
        p.push(0);
    }
    p
}

/// No peer sends more than `MAX_HEADERS_RESULTS` headers in one message
/// (main.cpp:696; the headers handler Core inherited refused a larger
/// count from its size alone, main.cpp.original:6502): 2000 decode, 2001
/// are refused from the count, before any header is read
#[test]
fn headers_edge() {
    match NetworkMessage::deserialize("headers", &headers_payload(MAX_HEADERS_RESULTS)).unwrap() {
        NetworkMessage::Headers(h) => assert_eq!(h.len(), MAX_HEADERS_RESULTS),
        other => panic!("{:?}", other),
    }
    assert!(
        NetworkMessage::deserialize("headers", &headers_payload(MAX_HEADERS_RESULTS + 1)).is_err()
    );
    // Refused from the count alone
    assert!(
        NetworkMessage::deserialize("headers", &compact(MAX_HEADERS_RESULTS as u64 + 1)).is_err()
    );
}

fn version_with_subver(len: usize) -> Vec<u8> {
    let mut v = VersionMessage {
        version: 70920,
        services: 1,
        timestamp: 0,
        addr_recv: NetAddr::from_ipv4([0; 4], 0, 0),
        addr_from: NetAddr::from_ipv4([0; 4], 0, 0),
        nonce: 1,
        user_agent: String::new(),
        start_height: 0,
        relay: true,
    }
    .serialize();
    // Replace the empty subversion (one zero byte after the nonce, 80 bytes in)
    let tail = v.split_off(81);
    v.truncate(80);
    v.extend(compact(len as u64));
    v.extend(std::iter::repeat_n(b'a', len));
    v.extend(tail);
    v
}

/// `LIMITED_STRING(strSubVer, 256)` (main.cpp:383)
#[test]
fn subversion_edge() {
    let ok = VersionMessage::deserialize(&version_with_subver(MAX_SUBVERSION_LENGTH)).unwrap();
    assert_eq!(ok.user_agent.len(), MAX_SUBVERSION_LENGTH);
    assert!(VersionMessage::deserialize(&version_with_subver(MAX_SUBVERSION_LENGTH + 1)).is_err());
}

/// The optional tail of a version message (main.cpp:379-390): each field
/// is read only if bytes remain, and a field cut in the middle is an error
#[test]
fn version_optional_fields() {
    let full = version_with_subver(3);
    // version, services, time, addrMe: 4 + 8 + 8 + 26
    let v = VersionMessage::deserialize(&full[..46]).unwrap();
    assert_eq!((v.nonce, v.start_height, v.relay), (1, -1, true));
    assert!(VersionMessage::deserialize(&full[..45]).is_err());
    assert!(VersionMessage::deserialize(&full[..50]).is_err());
    let v = VersionMessage::deserialize(&full[..full.len() - 1]).unwrap();
    assert!(v.relay);
    assert_eq!(v.user_agent, "aaa");
}

fn reject_payload(msg_len: usize, reason_len: usize) -> Vec<u8> {
    let mut p = compact(msg_len as u64);
    p.extend(std::iter::repeat_n(b'm', msg_len));
    p.push(0x10);
    p.extend(compact(reason_len as u64));
    p.extend(std::iter::repeat_n(b'r', reason_len));
    p
}

/// `LIMITED_STRING(strMsg, COMMAND_SIZE)` and
/// `LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH)` (main.cpp:946)
#[test]
fn reject_edges() {
    assert!(RejectMessage::deserialize(&reject_payload(12, 111)).is_ok());
    assert!(RejectMessage::deserialize(&reject_payload(13, 111)).is_err());
    assert!(RejectMessage::deserialize(&reject_payload(12, 112)).is_err());
}

/// The command of a message nobody knows is the message's own string: it
/// must not cost memory each time it is asked for
#[test]
fn unknown_command_is_borrowed() {
    let msg = NetworkMessage::Unknown("zzz".into(), vec![]);
    let NetworkMessage::Unknown(ref cmd, _) = msg else {
        unreachable!()
    };
    assert_eq!(msg.command(), "zzz");
    assert_eq!(msg.command().as_ptr(), cmd.as_ptr());
}

/// Bytes after a complete message are ignored, as Core leaves them unread
#[test]
fn trailing_bytes_are_ignored() {
    let mut p = NetworkMessage::Ping(9).serialize_payload().unwrap();
    p.extend_from_slice(b"extra");
    assert!(matches!(
        NetworkMessage::deserialize("ping", &p).unwrap(),
        NetworkMessage::Ping(9)
    ));
}

/// Inventory types Core does not define are read and kept as unknown
/// (protocol.cpp CInv, main.cpp inv handler ignores them)
#[test]
fn unknown_inventory_types_are_kept() {
    let mut p = vec![1u8];
    p.extend_from_slice(&99u32.to_le_bytes());
    p.extend_from_slice(&[0x22; 32]);
    match NetworkMessage::deserialize("inv", &p).unwrap() {
        NetworkMessage::Inv(v) => assert_eq!(v[0].inv_type, InvType::Unknown),
        other => panic!("{:?}", other),
    }
}
