//! Lane-E diagnostic: inspect stored stake modifiers and PoS kernel inputs
//! in an irondivid chainstate (run against a COPY of the datadir).
//!
//! usage:
//!   pos_diag <db> dump <height>
//!   pos_diag <db> recompute <from> <to>      (recompute modifiers, compare with stored)
//!   pos_diag <db> oracle <file>              (lines: height time bits txid vout value_sat kernel_time)
//!   pos_diag <db> utxo <txid> <vout>         (kernel UTXO + height index entry at its height)
//!   pos_diag <db> audit                      (read-only: stale height index entries)
//!   pos_diag <db> repair [testnet]           (open Chain -> one-time repair, then re-audit)
use divi_primitives::{Amount, Hash256, OutPoint};
use divi_storage::{
    compute_and_verify_proof_of_stake, compute_next_stake_modifier, ActivationState, BlockIndex,
    Chain, ChainDatabase, ChainParams, NetworkType, StakingData,
};
use std::collections::HashMap;
use std::str::FromStr;

fn idx_at(db: &ChainDatabase, h: u32) -> BlockIndex {
    db.get_block_index_by_height(h)
        .unwrap()
        .expect("no index at height")
}

fn show(i: &BlockIndex) {
    println!(
        "h={} hash={} time={} bits={:08x} mod={:016x} gen={} pos={}",
        i.height,
        i.hash,
        i.time,
        i.bits,
        i.stake_modifier,
        i.generated_stake_modifier,
        i.is_proof_of_stake
    );
}

fn hardened_modifier(db: &ChainDatabase, tip: &BlockIndex) -> (u64, u32) {
    let mut cur = tip.clone();
    loop {
        if cur.generated_stake_modifier {
            return (cur.stake_modifier, cur.height);
        }
        cur = db.get_block_index(&cur.prev_hash).unwrap().unwrap();
    }
}

fn recompute(db: &ChainDatabase, h: u32) -> (u64, bool) {
    let parent = idx_at(db, h - 1);
    let mut map: HashMap<Hash256, BlockIndex> = HashMap::new();
    let mut cur = Some(parent.clone());
    let mut n = 0;
    while let Some(i) = cur {
        map.insert(i.hash, i.clone());
        n += 1;
        if i.prev_hash.is_zero() || n >= 2000 {
            break;
        }
        cur = db.get_block_index(&i.prev_hash).unwrap();
    }
    let refs: HashMap<Hash256, &BlockIndex> = map.iter().map(|(k, v)| (*k, v)).collect();
    let gp = |p: &Hash256| refs.get(p).copied();
    let hard = ActivationState::new(&parent).is_hardened_stake_modifier_active();
    compute_next_stake_modifier(Some(refs[&parent.hash]), &gp, &refs, hard).unwrap()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let db = ChainDatabase::open(&a[1]).expect("open");
    println!(
        "best={:?} height={:?}",
        db.get_best_block().unwrap(),
        db.get_chain_height().unwrap()
    );
    match a[2].as_str() {
        "dump" => {
            let h: u32 = a[3].parse().unwrap();
            for k in (h.saturating_sub(5))..=h {
                if let Some(i) = db.get_block_index_by_height(k).unwrap() {
                    show(&i);
                }
            }
            let tip = idx_at(&db, h);
            let (m, mh) = hardened_modifier(&db, &tip);
            println!(
                "hardened modifier for child of {}: {:016x} (set at {})",
                h, m, mh
            );
        }
        "recompute" => {
            let from: u32 = a[3].parse().unwrap();
            let to: u32 = a[4].parse().unwrap();
            let mut bad = 0;
            for h in from..=to {
                let s = idx_at(&db, h);
                let (m, g) = recompute(&db, h);
                if m != s.stake_modifier || g != s.generated_stake_modifier {
                    bad += 1;
                    println!(
                        "MISMATCH h={} stored={:016x}/{} recomputed={:016x}/{}",
                        h, s.stake_modifier, s.generated_stake_modifier, m, g
                    );
                }
            }
            println!("recompute {}..={} mismatches={}", from, to, bad);
        }
        "oracle" => {
            let text = std::fs::read_to_string(&a[3]).unwrap();
            let (mut pass, mut fail) = (0, 0);
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let f: Vec<&str> = line.split_whitespace().collect();
                let h: u32 = f[0].parse().unwrap();
                let time: u32 = f[1].parse().unwrap();
                let bits = u32::from_str_radix(f[2], 16).unwrap();
                let txid = Hash256::from_str(f[3]).unwrap();
                let vout: u32 = f[4].parse().unwrap();
                let value: i64 = f[5].parse().unwrap();
                let ktime: u32 = f[6].parse().unwrap();
                let parent = match db.get_block_index_by_height(h - 1).unwrap() {
                    Some(p) => p,
                    None => {
                        println!("h={} parent missing", h);
                        continue;
                    }
                };
                let (m, mh) = hardened_modifier(&db, &parent);
                let sd = StakingData {
                    n_bits: bits,
                    block_time_of_first_confirmation: ktime,
                    block_hash_of_first_confirmation: Hash256::zero(),
                    utxo_being_staked: OutPoint { txid, vout },
                    utxo_value: Amount::from_sat(value),
                    block_hash_of_chain_tip: parent.hash,
                };
                let (hp, ok) = compute_and_verify_proof_of_stake(m, &sd, time).unwrap();
                if ok {
                    pass += 1
                } else {
                    fail += 1
                }
                println!("h={} ok={} mod={:016x}@{} hash={}", h, ok, m, mh, hp);
            }
            println!("oracle pass={} fail={}", pass, fail);
        }
        "utxo" => {
            let txid = Hash256::from_str(&a[3]).unwrap();
            let vout: u32 = a[4].parse().unwrap();
            match db.get_utxo(&OutPoint { txid, vout }).unwrap() {
                Some(u) => {
                    println!(
                        "utxo height={} value={} coinbase={} coinstake={}",
                        u.height,
                        u.value.as_sat(),
                        u.is_coinbase,
                        u.is_coinstake
                    );
                    show(&idx_at(&db, u.height));
                }
                None => println!("utxo not found"),
            }
        }
        "audit" => {
            // Read-only: active chain (tip -> genesis via prev_hash) vs height index.
            let mut cur = db
                .get_block_index(&db.get_best_block().unwrap().unwrap())
                .unwrap()
                .unwrap();
            let (mut checked, mut bad) = (0u64, 0u64);
            loop {
                checked += 1;
                let m = db.get_height_mapping(cur.height).unwrap();
                if m != Some(cur.hash) {
                    bad += 1;
                    if bad <= 20 {
                        println!("STALE h={} active={} mapped={:?}", cur.height, cur.hash, m);
                    }
                }
                if cur.height == 0 {
                    break;
                }
                cur = db.get_block_index(&cur.prev_hash).unwrap().unwrap();
            }
            println!("audit checked={} stale={}", checked, bad);
        }
        "repair" => {
            // Opening a Chain runs the one-time startup repair.
            drop(db);
            let db = std::sync::Arc::new(ChainDatabase::open(&a[1]).expect("open"));
            let net = match a.get(3).map(|s| s.as_str()) {
                Some("testnet") => NetworkType::Testnet,
                _ => NetworkType::Mainnet,
            };
            let chain = Chain::new(
                db,
                ChainParams::for_network(net, divi_primitives::ChainMode::Divi),
            )
            .expect("chain");
            let audit = chain.repair_height_index(false).unwrap();
            println!("post-repair audit: {:?}", audit);
        }
        _ => panic!("mode"),
    }
}
