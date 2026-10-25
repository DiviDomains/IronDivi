// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! A masternode set up and started on this node's wallet is listed as Divi
//! Core lists it: listmasternodes and getmasternodecount read the
//! masternodes the node took (its own broadcast first), in Core's form, and a
//! spent collateral shows once the masternodes are checked.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::mn_list::{payee_script, MasternodeList};
use divi_rpc::mn_votes::MasternodeVotes;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Node {
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    server: RpcServer,
    list: Arc<MasternodeList>,
    votes: Arc<MasternodeVotes>,
    sent: Arc<Mutex<Vec<Transaction>>>,
    dir: tempfile::TempDir,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let mut chain = Chain::new(
        db,
        ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
    )
    .unwrap();
    chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
    let chain = Arc::new(chain);
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        Network::Regtest,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain.clone(), wallet.clone());
    let list = Arc::new(MasternodeList::new());
    list.set_path(dir.path().join("masternodes.list"));
    server.set_masternode_list(list.clone());
    let votes = Arc::new(MasternodeVotes::new());
    server.set_masternode_votes(votes.clone());
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sink = sent.clone();
    server
        .wallet()
        .set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            sink.lock().push(tx);
            Ok(txid)
        }));
    Node {
        chain,
        wallet,
        server,
        list,
        votes,
        sent,
        dir,
    }
}

impl Node {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, (i32, String)> {
        let r = self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        });
        match r.error {
            Some(e) => Err((e.code, e.message)),
            None => Ok(r.result.unwrap()),
        }
    }

    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        self.call(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    /// Mine a block with the transactions sent so far; the coinbase pays the wallet
    fn mine(&self) {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        let to = self.wallet.new_receiving_address().unwrap();
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(1250 * COIN),
                Script::new_p2pkh(to.hash.as_bytes()),
            )],
            lock_time: 0,
        });
        block.transactions.extend(self.sent.lock().drain(..));
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        let time = block.header.time;
        let txs = block.transactions.clone();
        let hash = self.chain.accept_block(block).unwrap().hash;
        self.wallet.scan_block(hash, height, time, &txs);
        self.server.set_height(height);
    }

    fn mine_n(&self, n: usize) {
        for _ in 0..n {
            self.mine();
        }
    }
}

/// allocatefunds, setupmasternode and signmnbroadcast for `alias`: the
/// collateral (txhash, vout, address) and the signed broadcast
fn set_up(n: &Node, alias: &str, confirmations: usize) -> (String, u32, String, String) {
    let alloc = n.ok(
        "allocatefunds",
        vec![json!("masternode"), json!(alias), json!("copper")],
    );
    let txhash = alloc["txhash"].as_str().unwrap().to_string();
    let vout = alloc["vout"].as_u64().unwrap() as u32;
    n.mine_n(confirmations);
    let tx = n.ok("getrawtransaction", vec![json!(txhash), json!(1)]);
    let address = tx["vout"][vout as usize]["scriptPubKey"]["addresses"][0]
        .as_str()
        .unwrap()
        .to_string();
    let pubkey = n.ok("validateaddress", vec![json!(address)])["pubkey"].clone();
    let setup = n.ok(
        "setupmasternode",
        vec![
            json!(alias),
            json!(txhash),
            json!(vout.to_string()),
            pubkey,
            json!("127.0.0.2:53704"),
        ],
    );
    let signed = n.ok("signmnbroadcast", vec![setup["broadcast_data"].clone()]);
    *n_key(n).lock() = setup["config_line"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .nth(2)
        .map(String::from);
    (
        txhash,
        vout,
        address,
        signed["broadcast_data"].as_str().unwrap().to_string(),
    )
}

/// The masternode key of the last set_up, from its config line (WIF)
fn n_key(_n: &Node) -> &'static Mutex<Option<String>> {
    static KEY: Mutex<Option<String>> = parking_lot::const_mutex(None);
    &KEY
}

fn funded() -> Node {
    let n = node();
    n.mine_n(25);
    n
}

/// broadcaststartmasternode takes the broadcast into the node's own list
/// before relaying it (RpcMasternodeFeatures.cpp:80-121), and listmasternodes
/// gives Divi Core's fields (rpcmasternode.cpp:263-325): a loopback address
/// is no network (""), the address is the collateral's, the tier by name
#[test]
fn started_masternode_is_listed_as_divid_lists_it() {
    let n = funded();
    let (txhash, vout, address, signed) = set_up(&n, "mn1", 16);
    assert_eq!(n.ok("listmasternodes", vec![]), json!([]));
    assert_eq!(
        n.ok("broadcaststartmasternode", vec![json!(signed)]),
        json!({"status": "success"})
    );
    let listed = n.ok("listmasternodes", vec![]);
    let entry = &listed[0];
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    for (field, value) in [
        ("network", json!("")),
        ("txhash", json!(txhash)),
        ("outidx", json!(vout)),
        ("status", json!("ENABLED")),
        ("addr", json!(address)),
        ("version", json!(70915)),
        ("lastpaid", json!(0)),
        ("tier", json!("COPPER")),
    ] {
        assert_eq!(entry[field], value, "{field}: {listed}");
    }
    assert!(entry["lastseen"].as_i64().unwrap() > 0);
    // Filters on txhash, status or address (RpcMasternodeFeatures.cpp:293-301)
    assert_eq!(n.ok("listmasternodes", vec![json!("ENABLED")]), listed);
    assert_eq!(n.ok("listmasternodes", vec![json!(&address[2..9])]), listed);
    assert_eq!(n.ok("listmasternodes", vec![json!("nomatch")]), json!([]));
    // Below height 101 there is no block to score with, so no queue
    let count = n.ok("getmasternodecount", vec![]);
    for (field, value) in [
        ("total", 1),
        ("enabled", 1),
        ("obfcompat", 1),
        ("inqueue", 0),
        ("ipv4", 0),
    ] {
        assert_eq!(count[field], json!(value), "{field}: {count}");
    }
    // The list is kept in the datadir and read back, as mncache.dat
    let again = MasternodeList::new();
    again.set_path(n.dir.path().join("masternodes.list"));
    assert_eq!(again.list_json(&n.chain, None), listed);
}

/// A broadcast whose collateral has fewer than 15 confirmations is refused
/// (CheckInputsAndAdd, masternode.h:16): status failed, nothing listed
#[test]
fn broadcast_needs_fifteen_confirmations() {
    let n = funded();
    let (_, _, _, signed) = set_up(&n, "mn1", 10);
    assert_eq!(
        n.ok("broadcaststartmasternode", vec![json!(signed)]),
        json!({"status": "failed", "error": "Error processing broadcast"})
    );
    assert_eq!(n.ok("listmasternodes", vec![]), json!([]));
}

/// A spent collateral shows as VIN_SPENT once the masternodes are checked:
/// listmasternodes shows the last check's state, getmasternodecount checks
/// (masternodeman.cpp:152-180, RpcMasternodeFeatures.cpp:326-422)
#[test]
fn spent_collateral_shows_after_a_check() {
    let n = funded();
    let (txhash, vout, _, signed) = set_up(&n, "mn1", 16);
    n.ok("broadcaststartmasternode", vec![json!(signed)]);
    let hex = n.ok("getrawtransaction", vec![json!(txhash)]);
    let prev: Transaction =
        divi_primitives::serialize::deserialize(&hex::decode(hex.as_str().unwrap()).unwrap())
            .unwrap();
    let to = n.wallet.new_receiving_address().unwrap();
    let (mut tx, prevs) = TransactionBuilder::new()
        .add_input(
            OutPoint::new(prev.txid(), vout),
            prev.vout[vout as usize].script_pubkey.clone(),
        )
        .add_output_to_address(Amount::from_sat(99 * COIN), &to)
        .build();
    TransactionSigner::new(n.wallet.keystore())
        .sign_all_inputs(&mut tx, &prevs)
        .unwrap();
    n.sent.lock().push(tx);
    n.mine();
    assert_eq!(
        n.ok("listmasternodes", vec![])[0]["status"],
        json!("ENABLED")
    );
    let count = n.ok("getmasternodecount", vec![]);
    assert_eq!(
        (count["total"].clone(), count["enabled"].clone()),
        (json!(1), json!(0))
    );
    assert_eq!(
        n.ok("listmasternodes", vec![])[0]["status"],
        json!("VIN_SPENT")
    );
}

/// A payment vote (mnw) of a ranked masternode for the payee at the top of
/// the queue is counted and shown by getmasternodewinners; the same vote
/// again is not new, a second payee from the same masternode for the height
/// is refused, and so is a vote with a bad signature (masternode-payments.cpp
/// :203-267, MasternodePayeeData.cpp:44-66, rpcmasternode.cpp:489-578)
#[test]
fn payment_votes_are_counted_as_divid_counts_them() {
    let n = funded();
    let (txhash, vout, address, signed) = set_up(&n, "mn1", 16);
    let wif = n_key(&n).lock().clone().unwrap();
    n.ok("broadcaststartmasternode", vec![json!(signed)]);
    // A height is scored with the block 101 below it, and votes are taken up
    // to 20 above the tip: with proof of work up to 100, height 110
    while n.chain.height() < 100 {
        n.mine();
    }
    let height = 110;
    let key = divi_crypto::SecretKey::from_bytes(&divi_wallet::decode_wif(&wif).unwrap().key_bytes)
        .unwrap();
    let mnb = n.list.entries()[0].mnb.clone();
    let mut vote = divi_masternode::cpp_wire::CppWinner {
        vin: mnb.vin.clone(),
        height,
        payee: payee_script(&mnb),
        signature: vec![],
    };
    vote.sign(&key).unwrap();
    assert_eq!(n.votes.accept(&n.chain, &n.list, &vote.encode()), Ok(true));
    assert_eq!(n.votes.accept(&n.chain, &n.list, &vote.encode()), Ok(false));
    let winners = n.ok("getmasternodewinners", vec![json!("1")]);
    let at = winners
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["nHeight"] == json!(height))
        .unwrap();
    assert_eq!(at["winner"], json!({"address": address, "nVotes": 1}));
    let other = winners
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["nHeight"] == json!(height + 1))
        .unwrap();
    assert_eq!(other["winner"], json!({"address": "Unknown", "nVotes": 0}));

    let mut twice = vote.clone();
    twice.payee = vec![0x51];
    twice.sign(&key).unwrap();
    assert!(n.votes.accept(&n.chain, &n.list, &twice.encode()).is_err());
    let mut forged = vote.clone();
    forged.height = height + 1;
    assert!(n.votes.accept(&n.chain, &n.list, &forged.encode()).is_err());
    let _ = (txhash, vout);
}

/// The keys of the last set_up as secret keys: the collateral key (from the
/// wallet) and the masternode key (test-only throwaway regtest keys)
fn keys(n: &Node, address: &str) -> (divi_crypto::SecretKey, divi_crypto::SecretKey) {
    let secret = |wif: &str| {
        divi_crypto::SecretKey::from_bytes(&divi_wallet::decode_wif(wif).unwrap().key_bytes)
            .unwrap()
    };
    let collateral = n.ok("dumpprivkey", vec![json!(address)]);
    (
        secret(collateral.as_str().unwrap()),
        secret(&n_key(n).lock().clone().unwrap()),
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A broadcast is refused as Divi Core refuses one: a scriptSig on its
/// input, a tier that does not exist, a collateral that does not pay its
/// collateral key, a time before the collateral's 15th confirmation, an
/// attached ping naming an unknown block or one more than 24 below the tip;
/// an older broadcast than the listed one is refused and a newer one within
/// five minutes of it is not taken (masternodeman.cpp:196-307, :309-375,
/// :416-478)
#[test]
fn broadcasts_are_refused_as_divid_refuses_them() {
    use divi_masternode::cpp_wire::CppBroadcast;
    let n = funded();
    let (_, _, address, signed) = set_up(&n, "mn1", 16);
    let (coll_key, mn_key) = keys(&n, &address);
    let base = CppBroadcast::decode(&hex::decode(&signed).unwrap()).unwrap();
    let tip_hash = |depth: u32| {
        n.chain
            .get_block_index_by_height(n.chain.height() - depth)
            .unwrap()
            .unwrap()
            .hash
    };
    let make = |f: &dyn Fn(&mut CppBroadcast)| {
        let mut mnb = base.clone();
        mnb.sig_time = now();
        mnb.last_ping.sig_time = now();
        mnb.last_ping.block_hash = *tip_hash(2).as_bytes();
        f(&mut mnb);
        mnb.last_ping.sign(&mn_key).unwrap();
        mnb.sign(&coll_key).unwrap();
        mnb
    };
    let accept = |mnb: &CppBroadcast| n.list.accept_broadcast(&n.chain, &mnb.encode());
    let refused = |what: &str, mnb: CppBroadcast| {
        assert!(accept(&mnb).is_err(), "{what} was taken");
        assert!(n.list.entries().is_empty(), "{what} was listed");
    };
    refused("a scriptSig", make(&|m| m.vin.script_sig = vec![0x51]));
    refused("tier 7", make(&|m| m.tier = 7));
    let other = divi_crypto::SecretKey::new_random();
    let mut stranger = make(&|m| m.pubkey_collateral = other.public_key().to_bytes().to_vec());
    stranger.sign(&other).unwrap();
    refused("a collateral paying another key", stranger);
    let conf_time = n
        .chain
        .get_block_index_by_height(n.chain.height() - 1)
        .unwrap()
        .unwrap()
        .time as i64;
    refused(
        "a time before the 15th confirmation",
        make(&|m| m.sig_time = conf_time - 1000),
    );
    refused(
        "a ping naming an unknown block",
        make(&|m| m.last_ping.block_hash = [0xcd; 32]),
    );
    n.mine_n(30);
    refused(
        "a ping naming a block 30 deep",
        make(&|m| m.last_ping.block_hash = *tip_hash(30).as_bytes()),
    );

    let good = make(&|_| {});
    assert_eq!(accept(&good), Ok(true));
    let newer = make(&|m| m.sig_time = good.sig_time + 60);
    assert_eq!(accept(&newer), Ok(false));
    assert_eq!(n.list.entries()[0].mnb.sig_time, good.sig_time);
    let older = make(&|m| m.sig_time = good.sig_time - 60);
    assert!(accept(&older).is_err());
    assert_eq!(n.list.entries()[0].mnb.sig_time, good.sig_time);
}

/// A ping is taken as Divi Core takes one: not when it names an unknown
/// block or one more than 24 below the tip, nor a minute after the last
/// ping; a ping ten minutes on naming a recent block is
/// (masternodeman.cpp:309-375, MasternodeHelpers.cpp:172-190)
#[test]
fn pings_are_taken_as_divid_takes_them() {
    use divi_masternode::cpp_wire::{CppBroadcast, CppPing};
    let n = funded();
    let (_, _, address, signed) = set_up(&n, "mn1", 16);
    let (coll_key, mn_key) = keys(&n, &address);
    let block = |depth: u32| {
        *n.chain
            .get_block_index_by_height(n.chain.height() - depth)
            .unwrap()
            .unwrap()
            .hash
            .as_bytes()
    };
    let mut mnb = CppBroadcast::decode(&hex::decode(&signed).unwrap()).unwrap();
    mnb.sig_time = now();
    mnb.last_ping.sig_time = now() - 3000;
    mnb.last_ping.block_hash = block(2);
    mnb.last_ping.sign(&mn_key).unwrap();
    mnb.sign(&coll_key).unwrap();
    assert_eq!(n.list.accept_broadcast(&n.chain, &mnb.encode()), Ok(true));
    n.mine_n(30);
    let ping = |sig_time: i64, block_hash: [u8; 32]| {
        let mut p = CppPing {
            vin: mnb.vin.clone(),
            block_hash,
            sig_time,
            signature: vec![],
        };
        p.sign(&mn_key).unwrap();
        p.to_bytes()
    };
    let last_seen = || n.list.entries()[0].mnb.last_ping.sig_time;
    let first = last_seen();
    assert!(n
        .list
        .accept_ping(&n.chain, &ping(now(), [0xcd; 32]))
        .is_err());
    assert!(n
        .list
        .accept_ping(&n.chain, &ping(now(), block(30)))
        .is_err());
    assert_eq!(last_seen(), first);
    let good = now();
    assert_eq!(
        n.list.accept_ping(&n.chain, &ping(good, block(2))),
        Ok(true)
    );
    assert_eq!(last_seen(), good);
    assert!(n
        .list
        .accept_ping(&n.chain, &ping(good + 60, block(2)))
        .is_err());
    assert_eq!(last_seen(), good);
}

/// A refused broadcast or ping carries the misbehaviour score Divi Core
/// gives its sender: 1 for a time out of range, 20 for a tier that does not
/// exist, 100 for a bad broadcast signature, 33 for a collateral that does
/// not match and for a bad ping signature, none for the others
/// (masternodeman.cpp:232-265, :309-375, :420-466, :504-534)
#[test]
fn refusals_carry_divids_misbehaviour_scores() {
    use divi_masternode::cpp_wire::{CppBroadcast, CppPing};
    let n = funded();
    let (_, _, address, signed) = set_up(&n, "mn1", 16);
    let (coll_key, mn_key) = keys(&n, &address);
    let recent = *n
        .chain
        .get_block_index_by_height(n.chain.height() - 2)
        .unwrap()
        .unwrap()
        .hash
        .as_bytes();
    let base = CppBroadcast::decode(&hex::decode(&signed).unwrap()).unwrap();
    let make = |f: &dyn Fn(&mut CppBroadcast)| {
        let mut mnb = base.clone();
        mnb.sig_time = now();
        mnb.last_ping.sig_time = now() - 3000;
        mnb.last_ping.block_hash = recent;
        f(&mut mnb);
        mnb.last_ping.sign(&mn_key).unwrap();
        mnb.sign(&coll_key).unwrap();
        mnb
    };
    let score = |mnb: CppBroadcast| {
        n.list
            .accept_broadcast(&n.chain, &mnb.encode())
            .unwrap_err()
            .dos
    };
    let other = divi_crypto::SecretKey::new_random();
    assert_eq!(score(make(&|m| m.sig_time = now() + 7200)), 1);
    assert_eq!(score(make(&|m| m.tier = 7)), 20);
    assert_eq!(score(make(&|m| m.protocol_version = 70914)), 0);
    assert_eq!(score(make(&|m| m.vin.script_sig = vec![0x51])), 0);
    let mut forged = make(&|_| {});
    forged.sign(&other).unwrap();
    assert_eq!(score(forged), 100);
    let mut stranger = make(&|m| m.pubkey_collateral = other.public_key().to_bytes().to_vec());
    stranger.sign(&other).unwrap();
    assert_eq!(score(stranger), 33);
    let mut bad_ping = make(&|_| {});
    bad_ping.last_ping.sign(&other).unwrap();
    bad_ping.sign(&coll_key).unwrap();
    assert_eq!(score(bad_ping), 33);
    assert_eq!(score(make(&|m| m.last_ping.sig_time = now() + 7200)), 1);
    assert_eq!(score(make(&|m| m.last_ping.block_hash = [0xcd; 32])), 0);

    let good = make(&|_| {});
    assert_eq!(n.list.accept_broadcast(&n.chain, &good.encode()), Ok(true));
    let ping = |sig_time: i64, key: &divi_crypto::SecretKey| {
        let mut p = CppPing {
            vin: good.vin.clone(),
            block_hash: recent,
            sig_time,
            signature: vec![],
        };
        p.sign(key).unwrap();
        n.list.accept_ping(&n.chain, &p.to_bytes())
    };
    assert_eq!(ping(now(), &other).unwrap_err().dos, 33);
    assert_eq!(ping(now() + 7200, &mn_key).unwrap_err().dos, 1);
    assert_eq!(ping(now() - 7200, &mn_key).unwrap_err().dos, 1);
    assert_eq!(ping(now(), &mn_key), Ok(true));
    assert_eq!(ping(now() + 60, &mn_key).unwrap_err().dos, 0);
}

/// A broadcast or ping taken is kept by hash for peers that ask for it and
/// left to relay by inv, once; a broadcast seen before is not taken again
/// (masternodeman.cpp:420-426, :486-499, :504-517;
/// MasternodeNetworkMessageManager.cpp:236-266)
#[test]
fn taken_items_are_kept_and_left_to_relay() {
    use divi_masternode::cpp_wire::{CppBroadcast, CppPing};
    use divi_rpc::mn_list::{INV_BROADCAST, INV_PING};
    let n = funded();
    let (_, _, address, signed) = set_up(&n, "mn1", 16);
    let (coll_key, mn_key) = keys(&n, &address);
    let recent = *n
        .chain
        .get_block_index_by_height(n.chain.height() - 2)
        .unwrap()
        .unwrap()
        .hash
        .as_bytes();
    let mut mnb = CppBroadcast::decode(&hex::decode(&signed).unwrap()).unwrap();
    mnb.sig_time = now();
    mnb.last_ping.sig_time = now() - 3000;
    mnb.last_ping.block_hash = recent;
    mnb.last_ping.sign(&mn_key).unwrap();
    mnb.sign(&coll_key).unwrap();
    assert_eq!(n.list.take_relays(), vec![]);
    assert_eq!(n.list.accept_broadcast(&n.chain, &mnb.encode()), Ok(true));
    assert_eq!(n.list.take_relays(), vec![(INV_BROADCAST, mnb.hash())]);
    assert_eq!(n.list.seen_broadcast(&mnb.hash()), Some(mnb.encode()));
    assert!(n.list.has(INV_BROADCAST, &mnb.hash()));
    assert!(n.list.has(INV_PING, &mnb.last_ping.hash()));
    assert_eq!(n.list.accept_broadcast(&n.chain, &mnb.encode()), Ok(false));
    assert_eq!(n.list.take_relays(), vec![]);

    let mut ping = CppPing {
        vin: mnb.vin.clone(),
        block_hash: recent,
        sig_time: now(),
        signature: vec![],
    };
    ping.sign(&mn_key).unwrap();
    assert_eq!(n.list.accept_ping(&n.chain, &ping.to_bytes()), Ok(true));
    assert_eq!(n.list.take_relays(), vec![(INV_PING, ping.hash())]);
    assert_eq!(n.list.seen_ping(&ping.hash()), Some(ping.to_bytes()));
    assert_eq!(n.list.accept_ping(&n.chain, &ping.to_bytes()), Ok(false));
    assert_eq!(n.list.take_relays(), vec![]);
    // The broadcast a peer gets carries the last ping (recordLastPing)
    let shared = CppBroadcast::decode(&n.list.seen_broadcast(&mnb.hash()).unwrap()).unwrap();
    assert_eq!(shared.last_ping, ping);
}
