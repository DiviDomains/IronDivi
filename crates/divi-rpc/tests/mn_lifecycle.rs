// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! A masternode's life as Divi Core sees it from a controller: its start
//! answered as the list took it, its state on the node's clock as its pings
//! stop, a collateral spent after it expired, what the list forgets, the
//! payment queue off regtest, the collateral found without the transaction
//! index or in the mempool, the alias's masternode key, and the order of the
//! stored broadcasts.
//!
//! Some tests move the node's clock (setmocktime), which every test in this
//! binary reads, so they run one at a time.

use divi_crypto::compute_merkle_root;
use divi_masternode::cpp_wire::{CppBroadcast, CppWinner};
use divi_primitives::{
    amount::Amount,
    block::Block,
    clock,
    hash::Hash256,
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::blockchain::MempoolProvider;
use divi_rpc::mn_list::{payee_script, MasternodeList};
use divi_rpc::mn_votes::MasternodeVotes;
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{txindex::TxIndex, Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, TransactionBuilder, TransactionSigner, WalletDb};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

/// One test at a time: some set the node's clock
static SERIAL: Mutex<()> = Mutex::new(());

/// The node's clock set to `time` until dropped
struct MockTime;

impl MockTime {
    fn at(time: i64) -> Self {
        clock::set_mock_time(time);
        MockTime
    }
}

impl Drop for MockTime {
    fn drop(&mut self) {
        clock::set_mock_time(0);
    }
}

/// The transactions sent and not yet mined, as the node's mempool
struct Pool(Arc<Mutex<Vec<Transaction>>>);

impl MempoolProvider for Pool {
    fn get_txids(&self) -> Vec<Hash256> {
        self.0.lock().iter().map(|t| t.txid()).collect()
    }

    fn prioritise_transaction(&self, _: &Hash256, _: f64, _: i64) -> bool {
        false
    }

    fn get_transaction(&self, txid: &Hash256) -> Option<Transaction> {
        self.0.lock().iter().find(|t| t.txid() == *txid).cloned()
    }
}

struct Node {
    /// Seconds between blocks
    step: u32,
    chain: Arc<Chain>,
    wallet: Arc<WalletDb>,
    server: RpcServer,
    list: Arc<MasternodeList>,
    votes: Arc<MasternodeVotes>,
    sent: Arc<Mutex<Vec<Transaction>>>,
}

/// A node on `network` with proof of work past height 100 (check_block_work
/// off), with or without the transaction index, its blocks `step` seconds apart
fn node_on(network: NetworkType, tx_index: bool) -> Node {
    node_stepped(network, tx_index, 60)
}

fn node_stepped(network: NetworkType, tx_index: bool, step: u32) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let params = ChainParams {
        check_block_work: false,
        ..ChainParams::for_network(network, ChainMode::Divi)
    };
    let mut chain = Chain::new(db, params).unwrap();
    if tx_index {
        chain.enable_tx_index(Arc::new(TxIndex::open(dir.path().join("txindex")).unwrap()));
    }
    // The directory lives as long as the test process; the databases hold it
    std::mem::forget(dir);
    let chain = Arc::new(chain);
    let wallet_network = match network {
        NetworkType::Mainnet => Network::Mainnet,
        NetworkType::Testnet => Network::Testnet,
        NetworkType::Regtest => Network::Regtest,
    };
    let wallet = Arc::new(WalletDb::with_hd_wallet(
        wallet_network,
        HdWallet::new(ChainMode::Divi).unwrap(),
    ));
    let server = RpcServer::with_wallet(chain.clone(), wallet.clone());
    let list = Arc::new(MasternodeList::new());
    server.set_masternode_list(list.clone());
    let votes = Arc::new(MasternodeVotes::new());
    server.set_masternode_votes(votes.clone());
    let sent = Arc::new(Mutex::new(Vec::new()));
    server.set_mempool(Arc::new(Pool(sent.clone())));
    let sink = sent.clone();
    server
        .wallet()
        .set_tx_submit(Arc::new(move |tx: Transaction| {
            let txid = tx.txid();
            sink.lock().push(tx);
            Ok(txid)
        }));
    let n = Node {
        step,
        chain,
        wallet,
        server,
        list,
        votes,
        sent,
    };
    n.mine_n(25);
    n
}

fn regtest() -> Node {
    node_on(NetworkType::Regtest, true)
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

    /// A block with the transactions sent so far; the coinbase pays the
    /// wallet, at height 1 a premine large enough for mainnet collaterals
    fn mine(&self) {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + self.step;
        block.header.bits = 0x207fffff;
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        let to = self.wallet.new_receiving_address().unwrap();
        let value = match height {
            1 => 1_000_000 * COIN,
            2..=100 => 1250 * COIN,
            _ => COIN,
        };
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(
                Amount::from_sat(value),
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

    /// allocatefunds for `alias` of `tier`
    fn allocate(&self, alias: &str, tier: &str) -> (String, u32) {
        let alloc = self.ok(
            "allocatefunds",
            vec![json!("masternode"), json!(alias), json!(tier)],
        );
        (
            alloc["txhash"].as_str().unwrap().to_string(),
            alloc["vout"].as_u64().unwrap() as u32,
        )
    }

    /// The collateral's address: its transaction is in the mempool or the chain
    fn collateral_address(&self, txhash: &str, vout: u32) -> String {
        let hash = Hash256::from_hex(txhash).unwrap();
        let pooled = self.sent.lock().iter().find(|t| t.txid() == hash).cloned();
        let tx = pooled
            .or_else(|| {
                self.chain
                    .locate_transaction(&hash)
                    .unwrap()
                    .map(|(t, _)| t)
            })
            .unwrap();
        let script = tx.vout[vout as usize].script_pubkey.as_bytes().to_vec();
        let mut id = [0u8; 20];
        id.copy_from_slice(&script[3..23]);
        divi_wallet::address::Address::from_pubkey_hash(id.into(), self.wallet.network())
            .to_base58()
    }

    /// setupmasternode for a collateral the wallet funded
    fn setup(&self, alias: &str, txhash: &str, vout: u32) -> Result<Value, (i32, String)> {
        let address = self.collateral_address(txhash, vout);
        let pubkey = self.ok("validateaddress", vec![json!(address)])["pubkey"].clone();
        self.call(
            "setupmasternode",
            vec![
                json!(alias),
                json!(txhash),
                json!(vout.to_string()),
                pubkey,
                json!("127.0.0.2:53704"),
            ],
        )
    }

    /// allocatefunds, 16 blocks, setupmasternode and signmnbroadcast: the
    /// collateral, the signed broadcast and the masternode key
    fn set_up(&self, alias: &str, tier: &str) -> Started {
        let (txhash, vout) = self.allocate(alias, tier);
        self.mine_n(16);
        let setup = self.setup(alias, &txhash, vout).unwrap();
        let signed = self.ok("signmnbroadcast", vec![setup["broadcast_data"].clone()]);
        let wif = setup["config_line"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .nth(2)
            .unwrap()
            .to_string();
        Started {
            txhash,
            vout,
            signed: signed["broadcast_data"].as_str().unwrap().to_string(),
            key: divi_crypto::SecretKey::from_bytes(
                &divi_wallet::decode_wif(&wif).unwrap().key_bytes,
            )
            .unwrap(),
        }
    }

    /// set_up, then broadcaststartmasternode, answered success
    fn start(&self, alias: &str, tier: &str) -> Started {
        let s = self.set_up(alias, tier);
        assert_eq!(
            self.ok("broadcaststartmasternode", vec![json!(s.signed)]),
            json!({"status": "success"})
        );
        s
    }

    /// Spend a collateral in the next block
    fn spend(&self, s: &Started) {
        let hash = Hash256::from_hex(&s.txhash).unwrap();
        let (prev, _) = self.chain.locate_transaction(&hash).unwrap().unwrap();
        let to = self.wallet.new_receiving_address().unwrap();
        let out = &prev.vout[s.vout as usize];
        let (mut tx, prevs) = TransactionBuilder::new()
            .add_input(OutPoint::new(hash, s.vout), out.script_pubkey.clone())
            .add_output_to_address(Amount::from_sat(out.value.0 - COIN / 100), &to)
            .build();
        TransactionSigner::new(self.wallet.keystore())
            .sign_all_inputs(&mut tx, &prevs)
            .unwrap();
        self.sent.lock().push(tx);
        self.mine();
    }

    fn status(&self, s: &Started) -> Value {
        let listed = self.ok("listmasternodes", vec![json!(s.txhash)]);
        listed
            .as_array()
            .unwrap()
            .first()
            .map_or(json!(null), |e| e["status"].clone())
    }

    fn last_ping_time(&self) -> i64 {
        self.list.entries()[0].mnb.last_ping.sig_time
    }
}

struct Started {
    txhash: String,
    vout: u32,
    signed: String,
    key: divi_crypto::SecretKey,
}

/// broadcaststartmasternode answers whether the node's list took the
/// broadcast (RelayParsedMasternodeBroadcast, RpcMasternodeFeatures.cpp
/// :104-121). A broadcast whose ping names a block more than 24 below the tip
/// is refused by the list (masternodeman.cpp:342-352): failed, as on divid
#[test]
fn a_broadcast_the_list_refuses_is_answered_failed() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.set_up("mn1", "copper");
    // The ping names the block 12 below the tip at setup: 13 more blocks put
    // it 25 below
    n.mine_n(13);
    assert_eq!(
        n.ok("broadcaststartmasternode", vec![json!(s.signed)]),
        json!({"status": "failed", "error": "Error processing broadcast"})
    );
    assert_eq!(n.ok("listmasternodes", vec![]), json!([]));
}

/// The same broadcast once listed is success again: ProcessBroadcast takes a
/// broadcast it has seen as done (masternodeman.cpp:420-424)
#[test]
fn a_broadcast_already_listed_is_answered_success() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.start("mn1", "copper");
    assert_eq!(
        n.ok("broadcaststartmasternode", vec![json!(s.signed)]),
        json!({"status": "success"})
    );
    assert_eq!(n.ok("listmasternodes", vec![]).as_array().unwrap().len(), 1);
}

/// With its pings stopped a masternode is EXPIRED once its last ping is two
/// hours old and REMOVE at 130 minutes, on the node's clock, which
/// setmocktime sets: TimeSinceLastPingIsWithin (MasternodeHelpers.cpp
/// :172-181) is `now - sigTime < window` on GetAdjustedTime
#[test]
fn a_masternode_expires_on_the_nodes_clock() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.start("mn1", "copper");
    let ping = n.last_ping_time();
    for (after, status) in [
        (7199, "ENABLED"),
        (7200, "EXPIRED"),
        (7799, "EXPIRED"),
        (7800, "REMOVE"),
    ] {
        let _clock = MockTime::at(ping + after);
        n.ok("getmasternodecount", vec![]);
        assert_eq!(n.status(&s), json!(status), "{after} s after the last ping");
        let count = n.ok("getmasternodecount", vec![]);
        assert_eq!(
            count["enabled"],
            json!(usize::from(status == "ENABLED")),
            "{after} s: {count}"
        );
    }
}

/// Check looks at the collateral only after the ping times
/// (masternodeman.cpp:160-178): a masternode that expired and then had its
/// collateral spent stays EXPIRED, and leaves the list at REMOVE, 130 minutes
/// after its last ping, not at the next minute's pass
#[test]
fn an_expired_masternode_whose_collateral_is_spent_stays_expired() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.start("mn1", "copper");
    let ping = n.last_ping_time();
    let _clock = MockTime::at(ping + 7300);
    n.ok("getmasternodecount", vec![]);
    assert_eq!(n.status(&s), json!("EXPIRED"));
    n.spend(&s);
    let count = n.ok("getmasternodecount", vec![]);
    assert_eq!(n.status(&s), json!("EXPIRED"), "{count}");
    n.list.remove_inactive(ping + 7300);
    assert_eq!(n.status(&s), json!("EXPIRED"));
    n.list.remove_inactive(ping + 7800);
    assert_eq!(n.ok("listmasternodes", vec![]), json!([]));
}

/// An enabled masternode whose collateral is spent is VIN_SPENT, and stays
/// so (masternodeman.cpp:160-178)
#[test]
fn an_enabled_masternode_whose_collateral_is_spent_is_vin_spent() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.start("mn1", "copper");
    n.spend(&s);
    n.ok("getmasternodecount", vec![]);
    assert_eq!(n.status(&s), json!("VIN_SPENT"));
    let _clock = MockTime::at(n.last_ping_time() + 7300);
    assert_eq!(n.status(&s), json!("VIN_SPENT"));
}

/// The minute's pass forgets the pings and broadcasts it saw whose ping is
/// more than twice the removal time old (clearTimedOutMasternodePings,
/// clearTimedOutMasternodeBroadcasts, MasternodeNetworkMessageManager.cpp
/// :106-131): a peer asking for one then gets `notfound`
#[test]
fn old_pings_and_broadcasts_are_forgotten() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let a = n.start("mn1", "copper");
    let b = n.start("mn2", "copper");
    let first = n.list.entries()[0].mnb.clone();
    let ping = first.last_ping.hash();
    assert!(n.list.seen_ping(&ping).is_some());
    assert!(n.list.seen_broadcast(&first.hash()).is_some());
    // Within twice the removal time both are kept, though the masternodes
    // are gone
    let time = first.last_ping.sig_time;
    n.list.remove_inactive(time + 2 * 7800);
    assert_eq!(n.ok("listmasternodes", vec![]), json!([]));
    assert!(n.list.seen_ping(&ping).is_some());
    n.list.remove_inactive(time + 2 * 7800 + 1);
    assert!(n.list.seen_ping(&ping).is_none());
    let _ = (a, b);
}

/// Votes more than 1000 blocks below the tip are pruned once a minute
/// (PruneOldMasternodeWinnerData, MasternodeModule.cpp:515-519,
/// MasternodePaymentData.cpp:46-61), not only when a vote is taken
#[test]
fn old_votes_are_pruned_without_a_new_vote() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.start("mn1", "copper");
    while n.chain.height() < 104 {
        n.mine();
    }
    let height = n.chain.height() as i32 + 1;
    let mnb = n.list.entries()[0].mnb.clone();
    let mut vote = CppWinner {
        vin: mnb.vin.clone(),
        height,
        payee: payee_script(&mnb),
        signature: vec![],
    };
    vote.sign(&s.key).unwrap();
    // Ranked: its broadcast was signed at an old block's time
    assert_eq!(n.votes.accept(&n.chain, &n.list, &vote.encode()), Ok(true));
    n.votes.prune_old(i64::from(height) + 1000);
    assert!(n.votes.is_known(&vote.hash()));
    n.votes.prune_old(i64::from(height) + 1001);
    assert!(!n.votes.is_known(&vote.hash()));
}

/// Off regtest the payment queue leaves out a masternode that has the most
/// votes for one of the next eight blocks (IsScheduled, masternode-payments
/// .cpp:332-352, :451-458), so getmasternodecount's inqueue does not count it
#[test]
fn a_scheduled_masternode_is_not_in_the_queue_off_regtest() {
    let _serial = SERIAL.lock();
    for (network, inqueue) in [(NetworkType::Testnet, 1), (NetworkType::Regtest, 2)] {
        // Off regtest setupmasternode wants a recent tip, and a masternode
        // votes 8000 s after its broadcast was signed (masternode-payments.cpp
        // :557-558) while its ping is under two hours old: the testnet chain
        // is made a second a block, its clock just past the tip for the
        // setups and 8100 s on for the vote
        let testnet = network == NetworkType::Testnet;
        let n = node_stepped(network, true, if testnet { 1 } else { 60 });
        let start = i64::from(n.chain.tip().unwrap().time) + 60;
        let mut clock = testnet.then(|| MockTime::at(start));
        let a = n.start("mn1", "copper");
        let b = n.start("mn2", "copper");
        while n.chain.height() < 120 {
            n.mine();
        }
        if testnet {
            drop(clock.take());
            clock = Some(MockTime::at(start + 8100));
        }
        let entries = n.list.entries();
        let count = n.ok("getmasternodecount", vec![]);
        assert_eq!(
            count["inqueue"],
            json!(2),
            "{network:?} before the vote: {count}"
        );
        // mn1 votes itself the payee of the next block
        let voter = &entries[0].mnb;
        let mut vote = CppWinner {
            vin: voter.vin.clone(),
            height: n.chain.height() as i32 + 1,
            payee: payee_script(voter),
            signature: vec![],
        };
        let key = if voter.pubkey_masternode == a.key.public_key().to_bytes() {
            &a.key
        } else {
            &b.key
        };
        vote.sign(key).unwrap();
        assert_eq!(
            n.votes.accept(&n.chain, &n.list, &vote.encode()),
            Ok(true),
            "{network:?}"
        );
        let count = n.ok("getmasternodecount", vec![]);
        assert_eq!(
            count["inqueue"],
            json!(inqueue),
            "{network:?} after the vote: {count}"
        );
        drop(clock);
    }
}

/// Without the transaction index the collateral is found through its unspent
/// output, as GetTransaction finds it (TransactionDiskAccessor.cpp:87-110):
/// the masternode is set up, started and listed
#[test]
fn a_masternode_starts_without_the_transaction_index() {
    let _serial = SERIAL.lock();
    let n = node_on(NetworkType::Regtest, false);
    let s = n.start("mn1", "copper");
    assert_eq!(n.status(&s), json!("ENABLED"));
    // A peer's broadcast of the collateral is not taken as a mismatch
    let mnb = n.list.entries()[0].mnb.clone();
    let other = MasternodeList::new();
    assert_eq!(other.accept_broadcast(&n.chain, &mnb.encode()), Ok(true));
}

/// setupmasternode finds a collateral still in the mempool, as
/// GetTransaction looks there first (TransactionDiskAccessor.cpp:58-61): its
/// ping names the tip and its broadcast is signed 45 minutes ahead
/// (MasternodeBroadcastFactory.cpp:212-224)
#[test]
fn setupmasternode_takes_a_collateral_in_the_mempool() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let (txhash, vout) = n.allocate("mn1", "copper");
    let setup = n
        .setup("mn1", &txhash, vout)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mnb =
        CppBroadcast::decode(&hex::decode(setup["broadcast_data"].as_str().unwrap()).unwrap())
            .unwrap();
    assert!(
        mnb.sig_time >= clock::adjusted_now() + 44 * 60,
        "{}",
        mnb.sig_time
    );
    assert_eq!(
        mnb.last_ping.block_hash,
        *n.chain.tip().unwrap().hash.as_bytes()
    );
}

/// setupmasternode's masternode key is the address of the account
/// "reserved-><alias>" (rpcmasternode.cpp:207): the same alias set up again
/// gets the same key while nothing pays it
#[test]
fn setupmasternode_keeps_the_alias_key() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let (txhash, vout) = n.allocate("mn1", "copper");
    n.mine();
    let key = |v: Value| {
        v["config_line"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .nth(2)
            .unwrap()
            .to_string()
    };
    let first = key(n.setup("mn1", &txhash, vout).unwrap());
    let again = key(n.setup("mn1", &txhash, vout).unwrap());
    assert_eq!(first, again);
    let other = key(n.setup("mn2", &txhash, vout).unwrap());
    assert_ne!(first, other);
    let reserved = n.ok("getaddressesbyaccount", vec![json!("reserved->mn1")]);
    assert_eq!(reserved.as_array().unwrap().len(), 1, "{reserved}");
}

/// listmnbroadcasts lists the stored broadcasts in std::map's order of their
/// collateral: the txid as a number, then the index
/// (StoredMasternodeBroadcasts.h:19, OutPoint.cpp:14-17), which is the order
/// of the txids as they are written
#[test]
fn listmnbroadcasts_is_in_collateral_order() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let mut want = Vec::new();
    for k in 0..6 {
        let s = n.set_up(&format!("mn{k}"), "copper");
        assert_eq!(
            n.ok("importmnbroadcast", vec![json!(s.signed)]),
            json!(true)
        );
        want.push(s.txhash);
    }
    want.sort();
    let listed: Vec<String> = n
        .ok("listmnbroadcasts", vec![])
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["txhash"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(listed, want);
}

/// Each tier's collateral on each network, as chainparams.cpp:136-152 has
/// them, is set up and started with its tier
#[test]
fn every_tier_is_set_up_and_listed() {
    let _serial = SERIAL.lock();
    let n = regtest();
    for (tier, name, amount) in [
        ("copper", "COPPER", 100),
        ("silver", "SILVER", 300),
        ("gold", "GOLD", 1000),
        ("platinum", "PLATINUM", 3000),
        ("diamond", "DIAMOND", 10000),
    ] {
        let s = n.start(tier, tier);
        let hash = Hash256::from_hex(&s.txhash).unwrap();
        let (tx, _) = n.chain.locate_transaction(&hash).unwrap().unwrap();
        assert_eq!(tx.vout[s.vout as usize].value.0, amount * COIN);
        let listed = n.ok("listmasternodes", vec![json!(s.txhash)]);
        assert_eq!(listed[0]["tier"], json!(name), "{listed}");
    }
}

/// The peers' time offset set until dropped (Core's nTimeOffset, which
/// GetAdjustedTime adds, timedata.cpp:35-38)
struct PeerOffset;

impl PeerOffset {
    fn of(seconds: i64) -> Self {
        clock::set_time_offset(seconds);
        PeerOffset
    }
}

impl Drop for PeerOffset {
    fn drop(&mut self) {
        clock::set_time_offset(0);
    }
}

/// A masternode's state is checked on the network-adjusted clock
/// (TimeSinceLastPingIsWithin on GetAdjustedTime, MasternodeHelpers.cpp
/// :172-181): with the node's own clock unmoved, a peer offset that puts the
/// adjusted time two hours past the last ping makes it EXPIRED
#[test]
fn a_peer_offset_moves_a_masternode_across_its_expiry() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.start("mn1", "copper");
    let since = clock::system_now() - n.last_ping_time();
    {
        let _offset = PeerOffset::of(7200 - since + 30);
        assert_eq!(n.status(&s), json!("EXPIRED"));
        let count = n.ok("getmasternodecount", vec![]);
        assert_eq!(count["enabled"], json!(0), "{count}");
    }
    assert_eq!(n.status(&s), json!("ENABLED"));
}

/// A broadcast is refused when signed more than an hour past the
/// network-adjusted clock (CheckMasternodeBroadcastContext,
/// masternodeman.cpp:235): a peer offset of ten minutes takes one signed 65
/// minutes ahead
#[test]
fn a_peer_offset_moves_the_broadcast_future_limit() {
    let _serial = SERIAL.lock();
    let n = regtest();
    let s = n.set_up("mn1", "copper");
    let mut mnb = CppBroadcast::decode(&hex::decode(&s.signed).unwrap()).unwrap();
    let hash = Hash256::from_hex(&s.txhash).unwrap();
    let (tx, _) = n.chain.locate_transaction(&hash).unwrap().unwrap();
    let script = tx.vout[s.vout as usize].script_pubkey.as_bytes().to_vec();
    let mut id = [0u8; 20];
    id.copy_from_slice(&script[3..23]);
    let address =
        divi_wallet::address::Address::from_pubkey_hash(id.into(), n.wallet.network()).to_base58();
    let wif = n.ok("dumpprivkey", vec![json!(address)]);
    let collateral = divi_crypto::SecretKey::from_bytes(
        &divi_wallet::decode_wif(wif.as_str().unwrap())
            .unwrap()
            .key_bytes,
    )
    .unwrap();
    mnb.sig_time = clock::system_now() + 65 * 60;
    mnb.sign(&collateral).unwrap();
    let refusal = MasternodeList::new()
        .accept_broadcast(&n.chain, &mnb.encode())
        .unwrap_err();
    assert_eq!(refusal.dos, 1, "{refusal}");
    let _offset = PeerOffset::of(10 * 60);
    assert_eq!(
        MasternodeList::new().accept_broadcast(&n.chain, &mnb.encode()),
        Ok(true)
    );
}
