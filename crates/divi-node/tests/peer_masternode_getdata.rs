// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! After a restart the masternodes the node kept are still known and served on
//! getdata, as Divi Core keeps its seen broadcasts and pings in mncache.dat
//! (MasternodeNetworkMessageManager.h:68-78; main.cpp:190-198): a broadcast by
//! its hash as `mnb`, its last ping as `mnp`; an item it lacks is answered with
//! `notfound`.

mod common;
use common::raw_peer::*;
use divi_masternode::cpp_wire::{CppBroadcast, CppPing, CppTxIn};

/// A broadcast as the list keeps it, on a public address, pinged now
fn broadcast() -> CppBroadcast {
    let vin = CppTxIn::new([0x11; 32], 1);
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..].copy_from_slice(&[8, 8, 4, 4]);
    let now = divi_primitives::clock::now();
    CppBroadcast {
        vin: vin.clone(),
        ip,
        port: 51476,
        pubkey_collateral: vec![2; 33],
        pubkey_masternode: vec![3; 33],
        signature: vec![0x1f; 65],
        sig_time: now - 100,
        protocol_version: 70920,
        last_ping: CppPing {
            vin,
            block_hash: [0x22; 32],
            sig_time: now - 10,
            signature: vec![0x1f; 65],
        },
        tier: 0,
    }
}

fn compact(n: usize) -> Vec<u8> {
    assert!(n < 0xfd);
    vec![n as u8]
}

/// CMasternodeBroadcast::GetHash: sigTime and the collateral key
fn broadcast_hash(b: &CppBroadcast) -> [u8; 32] {
    let mut d = b.sig_time.to_le_bytes().to_vec();
    d.extend_from_slice(&compact(b.pubkey_collateral.len()));
    d.extend_from_slice(&b.pubkey_collateral);
    sha256d(&d)
}

/// CMasternodePing::GetHash: the CTxIn (prevout, empty script, final
/// sequence) and sigTime
fn ping_hash(p: &CppPing) -> [u8; 32] {
    let mut d = p.vin.prevout_hash.to_vec();
    d.extend_from_slice(&p.vin.prevout_n.to_le_bytes());
    d.push(0);
    d.extend_from_slice(&u32::MAX.to_le_bytes());
    d.extend_from_slice(&p.sig_time.to_le_bytes());
    sha256d(&d)
}

fn getdata(inv_type: u32, hash: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(&inv_type.to_le_bytes());
    v.extend_from_slice(hash);
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn masternode_items_are_served_on_getdata() {
    let mnb = broadcast();
    let t = TestNode::start_with(|c| {
        let file = common::mncache::mncache_with(&mnb, c.network.magic);
        std::fs::write(c.data_dir.join("mncache.dat"), file).unwrap();
    })
    .await;
    let mut peer = RawPeer::connect(&t, "127.0.0.2").await;
    peer.handshake().await;

    peer.send("getdata", &getdata(14, &broadcast_hash(&mnb)))
        .await;
    assert_eq!(peer.expect("mnb", WAIT).await, Some(mnb.encode()));

    // The ping as `mnp` carries it
    let p = &mnb.last_ping;
    let mut ping = Vec::new();
    ping.extend_from_slice(&p.vin.prevout_hash);
    ping.extend_from_slice(&p.vin.prevout_n.to_le_bytes());
    ping.push(0);
    ping.extend_from_slice(&u32::MAX.to_le_bytes());
    ping.extend_from_slice(&p.block_hash);
    ping.extend_from_slice(&p.sig_time.to_le_bytes());
    ping.extend_from_slice(&compact(p.signature.len()));
    ping.extend_from_slice(&p.signature);
    peer.send("getdata", &getdata(15, &ping_hash(p))).await;
    assert_eq!(peer.expect("mnp", WAIT).await, Some(ping));

    // A winner the node does not have
    peer.send("getdata", &getdata(7, &[0x33; 32])).await;
    assert_eq!(
        peer.expect("notfound", WAIT).await,
        Some(getdata(7, &[0x33; 32]))
    );
}
