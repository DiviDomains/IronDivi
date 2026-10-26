// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! mncache.dat as Divi Core writes it for a list of one masternode, to start a
//! node with that list

#![allow(dead_code)]

use divi_masternode::cpp_wire::CppBroadcast;

/// The file for `mnb`, enabled, with its broadcast and last ping seen and
/// nothing asked for (MasternodeNetworkMessageManager.h:68-78; flat-database.h:59-97)
pub fn mncache_with(mnb: &CppBroadcast, network_magic: [u8; 4]) -> Vec<u8> {
    let magic = b"magicMasternodeCache";
    let mut out = vec![magic.len() as u8];
    out.extend_from_slice(magic);
    out.extend_from_slice(&network_magic);
    out.push(1);
    out.extend_from_slice(&mnb.encode_disk(0));
    // The three asked-for maps, then nDsqCount
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&0i64.to_le_bytes());
    out.push(1);
    out.extend_from_slice(&mnb.hash());
    out.extend_from_slice(&mnb.encode());
    out.push(1);
    out.extend_from_slice(&mnb.last_ping.hash());
    out.extend_from_slice(&mnb.last_ping.to_bytes());
    let checksum = divi_crypto::double_sha256(&out);
    out.extend_from_slice(&checksum);
    out
}
