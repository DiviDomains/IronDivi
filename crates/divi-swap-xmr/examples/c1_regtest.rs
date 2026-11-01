// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! C1 design tests 5 and 7 (`docs/plans/swap-poc/xmr-c1-design.md` §7) against a real Divi
//! C++ node on a private regtest chain. Results: `docs/plans/swap-poc/c1-regtest-results.md`.
//!
//! Needs two `divid -regtest` nodes, A and B (B peered to A, so it validates every block A
//! makes through the normal P2P path). Their datadirs are `$C1RT_DIR/a` and `$C1RT_DIR/b`
//! (default `/mnt/storage1/bshuler-xmr/c1-regtest`); each `divi.conf` carries `rpcuser`,
//! `rpcpassword` and `rpcport`. The password is read at runtime and never printed.
//!
//! Test 5: per malleated `Tx_cancel` encoding (a high-S `σ_J`, and `σ_J` in a non-minimal
//! `PUSHDATA1`), a fresh swap: `J` from two in-process 2P-ECDSA sessions, `Tx_lock` funded and
//! mined, `Tx_cancel` signed by `J`, the taker's 120 refund encsigs. The malleated `Tx_cancel`
//! goes to `sendrawtransaction` (result recorded), then into a block through `generateblock`'s
//! `extratx` with `ignoreMempool` (a staker including it directly; the block is still fully
//! consensus-validated by A and again by B). The maker then finds the encsig for the mined
//! txid, completes `Tx_refund`, broadcasts it normally and it is mined; the taker recovers
//! `s_m` from the mined refund.
//!
//! Test 7: `Tx_lock` whose own P2PKH input signature is S-flipped (different txid) is mined.
//! The presigned `Tx_cancel` (for the canonical txid) is refused by the mempool and by block
//! validation; the maker's late spend of the malleated outpoint is refused before `t_late` and
//! accepted and mined after it.
//!
//! Run on the regtest host: `cargo run --example c1_regtest -p divi-swap-xmr`.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use divi_crypto::keys::SecretKey;
use divi_crypto::signature::sign_hash;
use divi_primitives::amount::Amount;
use divi_primitives::script::Script;
use divi_primitives::serialize::{deserialize, serialize};
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::SigHashType;
use divi_swap::htlc::{push_data, REFUND_SEQUENCE};
use divi_swap_xmr::api::after_cancel;
use divi_swap_xmr::crypto::{self, Signer};
use divi_swap_xmr::jsig::{self, JSession, JStatus, Primes, MAKER, TAKER};
use divi_wallet::address::{Address, Network};
use divi_wallet::signer::sighash;
use serde_json::{json, Value};
use swap_adaptor::adaptor::{AdaptorSigner, EncryptedSignature};
use swap_adaptor::dleq::random_clamped_secret;
use swap_chain_divi::{RetryPolicy, RpcClient, RpcError};
use swap_chain_xmr::lock_scripts::{
    self, CancelScript, LockScript, LockSpend, CANCEL_VARIANTS, SEL_CANCEL,
};
use swap_chain_xmr::swap_templates::{maker_completes_tx_refund, taker_encrypts_tx_refund};

type R<T> = std::result::Result<T, String>;

macro_rules! ensure {
    ($c:expr, $($m:tt)*) => {
        if !$c {
            return Err(format!($($m)*));
        }
    };
}

/// Every lock holds this much; every presigned spend pays `FEE`.
const LOCK_SATS: u64 = 10 * 100_000_000;
const FEE: u64 = 1_000_000;
/// Each funding UTXO the node's wallet sends the harness.
const FUND_DIVI: f64 = 20.0;
/// CLTV and LIMIT_TRANSFER activate by median time past (`ForkActivation.cpp`).
const CLTV_ACTIVATION_MTP: u64 = 1_692_792_000;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------------------------
// The node

struct Node {
    name: &'static str,
    rpc: RpcClient,
    password: String,
}

impl Node {
    fn open(name: &'static str, datadir: &str) -> R<Node> {
        let conf = std::fs::read_to_string(format!("{datadir}/divi.conf"))
            .map_err(|e| format!("{name}: divi.conf: {e}"))?;
        let get = |k: &str| {
            conf.lines()
                .rev()
                .filter_map(|l| l.trim().strip_prefix(&format!("{k}=")))
                .next()
                .map(str::to_string)
        };
        let (user, password, port) = match (get("rpcuser"), get("rpcpassword"), get("rpcport")) {
            (Some(u), Some(p), Some(n)) => (u, p, n),
            _ => {
                return Err(format!(
                    "{name}: divi.conf lacks rpcuser/rpcpassword/rpcport"
                ))
            }
        };
        let url = format!("http://{user}:{password}@127.0.0.1:{port}/");
        let retry = RetryPolicy {
            attempts: 1,
            base_delay: Duration::from_millis(100),
        };
        Ok(Node {
            name,
            rpc: RpcClient::new(&url, retry),
            password,
        })
    }

    /// One RPC call; any error text has the password redacted.
    async fn call(&self, method: &str, params: Value) -> R<Value> {
        self.rpc.call(method, params).await.map_err(|e| {
            let t = match e {
                RpcError::Node { code, message } => format!("rpc {code}: {message}"),
                RpcError::Swap(s) => s.to_string(),
            };
            let t = if self.password.is_empty() {
                t
            } else {
                t.replace(&self.password, "***")
            };
            format!("{} {method}: {t}", self.name)
        })
    }

    async fn height(&self) -> R<u64> {
        self.call("getblockcount", json!([]))
            .await?
            .as_u64()
            .ok_or("height".into())
    }

    async fn tip(&self) -> R<String> {
        Ok(self
            .call("getbestblockhash", json!([]))
            .await?
            .as_str()
            .unwrap_or("")
            .to_string())
    }

    /// Median of the last 11 block times.
    async fn mtp(&self) -> R<u64> {
        let h = self.height().await?;
        let mut times = Vec::new();
        for i in h.saturating_sub(10)..=h {
            let hash = self.call("getblockhash", json!([i])).await?;
            let b = self.call("getblock", json!([hash])).await?;
            times.push(b["time"].as_u64().ok_or("block time")?);
        }
        times.sort();
        Ok(times[times.len() / 2])
    }

    /// Mine `n` blocks from the mempool the normal way.
    async fn mine(&self, n: u64) -> R<Vec<String>> {
        let h0 = self.height().await?;
        self.call("setgenerate", json!([n])).await?;
        let h1 = self.height().await?;
        ensure!(h1 == h0 + n, "setgenerate {n}: height {h0} -> {h1}");
        let mut out = Vec::new();
        for i in h0 + 1..=h1 {
            out.push(
                self.call("getblockhash", json!([i]))
                    .await?
                    .as_str()
                    .unwrap_or("")
                    .into(),
            );
        }
        Ok(out)
    }

    /// Mine one block holding exactly `txs` (plus coinbase), bypassing the mempool.
    async fn mine_direct(&self, txs: &[&Transaction]) -> R<String> {
        let hexes: Vec<String> = txs.iter().map(|t| hex::encode(serialize(*t))).collect();
        let v = self
            .call(
                "generateblock",
                json!([{"extratx": hexes, "ignoreMempool": true}]),
            )
            .await?;
        Ok(v.as_str().ok_or("generateblock: no hash")?.to_string())
    }

    async fn send(&self, tx: &Transaction) -> R<String> {
        let v = self
            .call("sendrawtransaction", json!([hex::encode(serialize(tx))]))
            .await?;
        Ok(v.as_str().unwrap_or("").to_string())
    }

    /// The mined transaction `txid` (verbose `getrawtransaction`), decoded, with its block
    /// hash and confirmations.
    async fn mined(&self, txid: &str) -> R<(Transaction, String, u64)> {
        let v = self.call("getrawtransaction", json!([txid, 1])).await?;
        let raw = hex::decode(v["hex"].as_str().ok_or("no hex")?).map_err(|e| e.to_string())?;
        let tx: Transaction = deserialize(&raw).map_err(|e| format!("decode {txid}: {e:?}"))?;
        let block = v["blockhash"].as_str().unwrap_or("").to_string();
        let conf = v["confirmations"].as_u64().unwrap_or(0);
        ensure!(
            tx.txid().to_hex() == txid,
            "{txid}: node returned {}",
            tx.txid().to_hex()
        );
        Ok((tx, block, conf))
    }
}

/// Wait (a few seconds at most) for B to reach A's tip: B validated A's blocks itself.
async fn synced(a: &Node, b: &Node) -> R<String> {
    let want = a.tip().await?;
    for _ in 0..60 {
        if b.tip().await? == want {
            return Ok(want);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "node B did not reach A's tip {want} (B: {})",
        b.tip().await?
    ))
}

// ---------------------------------------------------------------------------------------------
// Keys, funding, the 2P-ECDSA key J

fn p2pkh_spk(key: &SecretKey) -> Script {
    let pk = key.public_key().serialize_compressed();
    Script::new_p2pkh(divi_crypto::hash::hash160(&pk).as_bytes())
}

struct Funder {
    key: SecretKey,
    spk: Script,
}

#[derive(Clone)]
struct Utxo {
    op: OutPoint,
    value: u64,
}

impl Funder {
    /// The node's wallet sends us `n` UTXOs; they are mined.
    async fn fund(&self, a: &Node, n: usize) -> R<Vec<Utxo>> {
        let addr = Address::p2pkh(&self.key.public_key(), Network::Regtest).to_string();
        let mut txids = Vec::new();
        for _ in 0..n {
            let t = a.call("sendtoaddress", json!([addr, FUND_DIVI])).await?;
            txids.push(t.as_str().ok_or("sendtoaddress")?.to_string());
        }
        a.mine(1).await?;
        let mut out = Vec::new();
        for t in txids {
            let (tx, _, _) = a.mined(&t).await?;
            let vout = tx
                .vout
                .iter()
                .position(|o| o.script_pubkey == self.spk)
                .ok_or("no vout")?;
            out.push(Utxo {
                op: OutPoint::new(tx.txid(), vout as u32),
                value: tx.vout[vout].value.as_sat() as u64,
            });
        }
        Ok(out)
    }

    /// A signed P2PKH spend of `u` paying `amount` to `spk` and the rest (less `FEE`) back.
    fn pay(&self, u: &Utxo, spk: &Script, amount: u64) -> R<Transaction> {
        let mut tx = Transaction {
            version: 1,
            vin: vec![TxIn::new(u.op, Script::new(), 0xffff_ffff)],
            vout: vec![
                TxOut::new(Amount::from_sat(amount as i64), spk.clone()),
                TxOut::new(
                    Amount::from_sat((u.value - amount - FEE) as i64),
                    self.spk.clone(),
                ),
            ],
            lock_time: 0,
        };
        let sig = self.sig(&tx)?;
        tx.vin[0].script_sig = self.script_sig(&sig);
        Ok(tx)
    }

    fn sig(&self, tx: &Transaction) -> R<Vec<u8>> {
        let h = sighash(tx, 0, &self.spk, SigHashType::All, false).map_err(|e| e.to_string())?;
        let mut s = sign_hash(&self.key, h.as_bytes())
            .map_err(|e| e.to_string())?
            .to_der();
        s.push(SigHashType::All as u8);
        Ok(s)
    }

    fn script_sig(&self, sig: &[u8]) -> Script {
        let mut s = Vec::new();
        push_data(&mut s, sig);
        push_data(&mut s, &self.key.public_key().serialize_compressed());
        Script::from_bytes(s)
    }
}

fn load_primes() -> (Primes, Primes) {
    let path = std::env::temp_dir().join("divi-swap-xmr-test-primes.json");
    if let Some(p) = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        println!("primes: cached ({})", path.display());
        return p;
    }
    println!("primes: generating two Paillier prime sets (tens of seconds)...");
    let p = std::thread::scope(|s| {
        let a = s.spawn(jsig::generate_primes);
        let b = s.spawn(jsig::generate_primes);
        (a.join().unwrap(), b.join().unwrap())
    });
    let _ = std::fs::write(&path, serde_json::to_vec(&p).unwrap());
    p
}

/// Both sides of one swap's `J`, in process, driven the way the taker drives the maker.
struct J {
    taker: JSession,
    maker: JSession,
    joint: [u8; 33],
}

impl J {
    fn keygen(sid: &[u8], primes: &(Primes, Primes)) -> R<J> {
        let e = |e: divi_swap::SwapError| e.to_string();
        let taker = JSession::start(sid, TAKER, primes.0.clone());
        let maker = JSession::start(sid, MAKER, primes.1.clone());
        let mut to_maker = taker.round(vec![]).map_err(e)?.outgoing;
        let joint = loop {
            let m = maker.round(to_maker).map_err(e)?;
            let t = taker.round(m.outgoing).map_err(e)?;
            to_maker = t.outgoing;
            if let (JStatus::KeyReady(x), JStatus::KeyReady(y)) = (&m.status, &t.status) {
                ensure!(x == y, "the two sides disagree on J");
                break *x;
            }
        };
        Ok(J {
            taker,
            maker,
            joint,
        })
    }

    fn sign(&self, h: [u8; 32]) -> R<Vec<u8>> {
        let e = |e: divi_swap::SwapError| e.to_string();
        let mut to_taker = self.maker.sign(h).map_err(e)?.outgoing;
        let mut to_maker = self.taker.sign(h).map_err(e)?.outgoing;
        let (mut ts, mut ms) = (None, None);
        while ts.is_none() || ms.is_none() {
            if ms.is_none() {
                let m = self.maker.round(std::mem::take(&mut to_maker)).map_err(e)?;
                to_taker.extend(m.outgoing);
                if let JStatus::Signed(s) = m.status {
                    ms = Some(s);
                }
            }
            if ts.is_none() {
                let t = self.taker.round(std::mem::take(&mut to_taker)).map_err(e)?;
                to_maker.extend(t.outgoing);
                if let JStatus::Signed(s) = t.status {
                    ts = Some(s);
                }
            }
        }
        ensure!(ts == ms, "the two sides produced different signatures");
        Ok(ts.unwrap())
    }
}

/// `maker::spend`'s shape: one input at `REFUND_SEQUENCE`, one output.
fn spend(prevout: OutPoint, value: u64, to: Script, lock_time: u32) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(prevout, Script::new(), REFUND_SEQUENCE)],
        vout: vec![TxOut::new(Amount::from_sat(value as i64), to)],
        lock_time,
    }
}

/// One swap's keys and scripts, up to a signed (canonical) `Tx_cancel`.
struct Swap {
    maker_key: SecretKey,
    taker_key: SecretKey,
    s_m: swap_adaptor::dleq::ScalarQ,
    lock: LockScript,
    lock_redeem: Vec<u8>,
    cancel: CancelScript,
    cancel_redeem: Vec<u8>,
    t_cancel: u32,
    t_punish: u32,
}

impl Swap {
    fn new(joint: [u8; 33], t_cancel: u32, t_punish: u32, t_late: u32) -> Swap {
        let maker_key = SecretKey::new_random();
        let taker_key = SecretKey::new_random();
        let s_m = random_clamped_secret(&mut rand::thread_rng());
        let lock = LockScript {
            maker: maker_key.public_key().serialize_compressed(),
            taker: taker_key.public_key().serialize_compressed(),
            joint,
            t_cancel,
            t_late,
        };
        let cancel = CancelScript {
            maker: lock.maker,
            taker: lock.taker,
            t_punish,
        };
        Swap {
            lock_redeem: lock.redeem_script(),
            cancel_redeem: cancel.redeem_script(),
            maker_key,
            taker_key,
            s_m,
            lock,
            cancel,
            t_cancel,
            t_punish,
        }
    }

    fn maker_refund_script(&self) -> Script {
        p2pkh_spk(&self.maker_key)
    }

    fn taker_payout_script(&self) -> Script {
        p2pkh_spk(&self.taker_key)
    }

    fn y_point(&self) -> swap_adaptor::adaptor::Point {
        AdaptorSigner::new().encryption_key_for(&crypto::secp_of(&self.s_m))
    }

    /// The unsigned `Tx_cancel` of the lock at `lock_op` (as `persist_setup` builds it).
    fn tx_cancel(&self, lock_op: OutPoint) -> Transaction {
        spend(
            lock_op,
            LOCK_SATS - FEE,
            self.cancel.script_pubkey(),
            self.t_cancel,
        )
    }

    /// The taker's `finish_keying`: one refund encsig per encoding of the signed `Tx_cancel`,
    /// keyed by that encoding's txid.
    fn taker_encsigs(
        &self,
        tx_cancel: &Transaction,
        sig_j: &[u8],
    ) -> R<HashMap<String, EncryptedSignature>> {
        ensure!(
            crypto::verify_plain(tx_cancel, &self.lock_redeem, &self.lock.joint, sig_j),
            "sigma_J does not verify under J"
        );
        let variants = lock_scripts::cancel_variants(tx_cancel, sig_j, &self.lock_redeem);
        ensure!(
            variants.len() == CANCEL_VARIANTS,
            "{} variants",
            variants.len()
        );
        let y = self.y_point();
        let mut out = HashMap::new();
        for v in &variants {
            let (refund, _) = after_cancel(
                v,
                FEE,
                self.maker_refund_script().as_bytes(),
                self.taker_payout_script().as_bytes(),
                self.t_cancel,
                self.t_punish,
            );
            let (_, enc) = taker_encrypts_tx_refund(
                OutPoint::new(v.txid(), 0),
                &self.cancel_redeem,
                &self.taker_key,
                &y,
                refund.vout[0].clone(),
                refund.lock_time,
                refund.vin[0].sequence,
            )
            .map_err(|e| format!("taker encsig: {e}"))?;
            out.insert(v.txid().to_hex(), enc);
        }
        ensure!(out.len() == CANCEL_VARIANTS, "variant txids collide");
        Ok(out)
    }

    /// The maker's `Tx_refund` for the mined `cancel` (maker.rs: encsig by mined txid,
    /// `after_cancel`, `maker_completes_tx_refund`, `two_key`).
    fn maker_refund(
        &self,
        cancel: &Transaction,
        encsigs: &HashMap<String, EncryptedSignature>,
    ) -> R<Transaction> {
        let txid = cancel.txid().to_hex();
        let enc = encsigs.get(&txid).cloned().ok_or(format!(
            "Tx_cancel {txid} is not one of the encodings the taker signed"
        ))?;
        let (unsigned, _) = after_cancel(
            cancel,
            FEE,
            self.maker_refund_script().as_bytes(),
            self.taker_payout_script().as_bytes(),
            self.t_cancel,
            self.t_punish,
        );
        let taker_pt = crypto::point_of_pubkey(&self.lock.taker).map_err(|e| e.to_string())?;
        let t = maker_completes_tx_refund(
            unsigned,
            &self.cancel_redeem,
            &taker_pt,
            enc,
            &self.maker_key,
            &crypto::secp_of(&self.s_m),
        )
        .map_err(|e| format!("Tx_refund: {e}"))?;
        crypto::two_key(t, &self.cancel_redeem).map_err(|e| e.to_string())
    }
}

/// Fund and mine a canonical `Tx_lock` for `swap`; returns it and its lock outpoint.
async fn lock_funds(
    a: &Node,
    b: &Node,
    f: &Funder,
    u: &Utxo,
    swap: &Swap,
) -> R<(Transaction, OutPoint)> {
    let spk = swap.lock.script_pubkey();
    let tx = f.pay(u, &spk, LOCK_SATS)?;
    let id = a.send(&tx).await?;
    ensure!(
        id == tx.txid().to_hex(),
        "Tx_lock txid {id} vs {}",
        tx.txid().to_hex()
    );
    a.mine(1).await?;
    synced(a, b).await?;
    let (_, block, conf) = a.mined(&id).await?;
    ensure!(conf >= 1, "Tx_lock unconfirmed");
    println!("  Tx_lock {id} mined in {block}");
    Ok((tx.clone(), OutPoint::new(tx.txid(), 0)))
}

fn show(r: &R<String>) -> String {
    match r {
        Ok(v) => format!("ACCEPTED ({v})"),
        Err(e) => format!("REJECTED: {e}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Test 5

/// One malleated-`Tx_cancel` run. `encode` turns `σ_J` and the lock redeem script into the
/// malleated scriptSig.
async fn test5(
    label: &str,
    a: &Node,
    b: &Node,
    f: &Funder,
    u: &Utxo,
    primes: &(Primes, Primes),
    encode: impl Fn(&[u8], &[u8]) -> R<Vec<u8>>,
) -> R<()> {
    println!("\n== Test 5{label}");
    let n = now() as u32;
    // t_cancel already past (the cancel and refund are final now); punish and late far off.
    let (t_cancel, t_punish, t_late) = (n - 600, n + 3600, n + 7200);
    let sid = format!("c1rt-5{label}-{}", now());
    let j = J::keygen(sid.as_bytes(), primes)?;
    println!("  J = {}", hex::encode(j.joint));
    let swap = Swap::new(j.joint, t_cancel, t_punish, t_late);
    println!("  t_cancel={t_cancel} t_punish={t_punish} t_late={t_late}");
    let (_, lock_op) = lock_funds(a, b, f, u, &swap).await?;

    let unsigned = swap.tx_cancel(lock_op);
    let sig_j = j.sign(crypto::digest(&unsigned, &swap.lock_redeem).map_err(|e| e.to_string())?)?;
    let encsigs = swap.taker_encsigs(&unsigned, &sig_j)?;
    let mut canonical = unsigned.clone();
    canonical.vin[0].script_sig = lock_scripts::cancel_sig(&sig_j, &swap.lock_redeem);
    println!("  canonical Tx_cancel txid {}", canonical.txid().to_hex());

    let mut mal = unsigned.clone();
    mal.vin[0].script_sig = Script::from_bytes(encode(&sig_j, &swap.lock_redeem)?);
    let mal_id = mal.txid().to_hex();
    ensure!(
        mal_id != canonical.txid().to_hex(),
        "malleation left the txid unchanged"
    );
    ensure!(
        encsigs.contains_key(&mal_id),
        "malleated Tx_cancel is not among the 120 variants"
    );
    ensure!(
        lock_scripts::lock_spend_branch(&mal, &swap.lock_redeem) == Some(LockSpend::Cancel),
        "malleated Tx_cancel not classified as the cancel branch"
    );
    println!("  malleated Tx_cancel txid {mal_id}");
    println!(
        "  malleated scriptSig {}",
        hex::encode(mal.vin[0].script_sig.as_bytes())
    );

    let mempool = a.send(&mal).await;
    println!(
        "  sendrawtransaction(malleated Tx_cancel): {}",
        show(&mempool)
    );
    let block = a.mine_direct(&[&mal]).await?;
    let tip = synced(a, b).await?;
    ensure!(tip == block, "tip {tip} != generated {block}");
    let (onchain, in_block, _) = a.mined(&mal_id).await?;
    ensure!(
        in_block == block,
        "malleated Tx_cancel in {in_block}, expected {block}"
    );
    ensure!(
        onchain.vin[0].script_sig == mal.vin[0].script_sig,
        "the mined scriptSig is not the malleated one"
    );
    let (_, b_block, _) = b.mined(&mal_id).await?;
    ensure!(b_block == block, "node B has it in {b_block}");
    println!("  malleated Tx_cancel mined in block {block} (node B agrees)");

    // Maker: refund for the txid actually mined.
    let refund = swap.maker_refund(&onchain, &encsigs)?;
    ensure!(
        refund.vin[0].prevout.txid.to_hex() == mal_id,
        "refund spends the wrong Tx_cancel"
    );
    let rid = a.send(&refund).await.map_err(|e| {
        format!("FINDING: the maker's Tx_refund for the mined variant is not relayable: {e}")
    })?;
    ensure!(rid == refund.txid().to_hex(), "Tx_refund id {rid}");
    println!("  sendrawtransaction(Tx_refund): ACCEPTED ({rid})");
    let rblock = a.mine(1).await?.pop().unwrap_or_default();
    synced(a, b).await?;
    let (refund_onchain, r_in, conf) = a.mined(&rid).await?;
    ensure!(
        r_in == rblock && conf >= 1,
        "Tx_refund in {r_in} conf {conf}, expected {rblock}"
    );
    let (_, b_r, _) = b.mined(&rid).await?;
    ensure!(b_r == rblock, "node B has Tx_refund in {b_r}");
    println!("  Tx_refund {rid} mined in block {rblock} (node B agrees)");

    // Taker: recover s_m from the mined refund with the encsig for that variant.
    let spent = refund_onchain.vin[0].prevout.txid.to_hex();
    let enc = encsigs
        .get(&spent)
        .ok_or("taker has no encsig for the spent Tx_cancel")?;
    let got = crypto::recover(&refund_onchain, Signer::Taker, &swap.y_point(), enc)
        .ok_or("taker could not recover s_m")?;
    ensure!(got == swap.s_m, "recovered scalar is not s_m");
    println!("  taker recovered s_m from the mined Tx_refund: matches (value not printed)");
    println!("  Test 5{label}: PASS");
    Ok(())
}

/// (a) σ_J with S flipped to n − S (high-S), every push canonical.
fn high_s(sig: &[u8], redeem: &[u8]) -> R<Vec<u8>> {
    let f = lock_scripts::s_flip(sig).ok_or("s_flip")?;
    ensure!(f != sig, "s_flip did nothing");
    Ok(lock_scripts::cancel_sig(&f, redeem).as_bytes().to_vec())
}

/// (b) σ_J pushed with PUSHDATA1 (non-minimal), the rest canonical.
fn pushdata1_sig(sig: &[u8], redeem: &[u8]) -> R<Vec<u8>> {
    ensure!(sig.len() <= 0x4b, "sig len {}", sig.len());
    let mut s = vec![0x4c, sig.len() as u8];
    s.extend_from_slice(sig);
    s.push(0x50 + SEL_CANCEL); // OP_2
    push_data(&mut s, redeem);
    Ok(s)
}

// ---------------------------------------------------------------------------------------------
// Test 7

async fn test7(a: &Node, b: &Node, f: &Funder, u: &Utxo, primes: &(Primes, Primes)) -> R<()> {
    println!("\n== Test 7");
    let n = now() as u32;
    // Cancel and punish already past; t_late shortly ahead so "before" and "after" both show.
    let (t_cancel, t_punish, t_late) = (n - 600, n - 300, n + 90);
    let sid = format!("c1rt-7-{}", now());
    let j = J::keygen(sid.as_bytes(), primes)?;
    println!("  J = {}", hex::encode(j.joint));
    let swap = Swap::new(j.joint, t_cancel, t_punish, t_late);
    println!("  t_cancel={t_cancel} t_punish={t_punish} t_late={t_late}");

    // The canonical Tx_lock, and the presigned Tx_cancel both sides sign for it.
    let canon = f.pay(u, &swap.lock.script_pubkey(), LOCK_SATS)?;
    let canon_id = canon.txid().to_hex();
    let unsigned = swap.tx_cancel(OutPoint::new(canon.txid(), 0));
    let sig_j = j.sign(crypto::digest(&unsigned, &swap.lock_redeem).map_err(|e| e.to_string())?)?;
    let _encsigs = swap.taker_encsigs(&unsigned, &sig_j)?;
    let mut tx_cancel = unsigned.clone();
    tx_cancel.vin[0].script_sig = lock_scripts::cancel_sig(&sig_j, &swap.lock_redeem);
    println!("  canonical Tx_lock txid {canon_id} (never broadcast)");
    println!(
        "  presigned Tx_cancel {} (spends {canon_id}:0)",
        tx_cancel.txid().to_hex()
    );

    // A staker re-encodes Tx_lock's own input signature: S -> n - S.
    let items = lock_scripts::stack_items(canon.vin[0].script_sig.as_bytes()).ok_or("p2pkh sig")?;
    let flipped = lock_scripts::s_flip(&items[0]).ok_or("s_flip")?;
    let mut mal = canon.clone();
    mal.vin[0].script_sig = f.script_sig(&flipped);
    let mal_id = mal.txid().to_hex();
    ensure!(mal_id != canon_id, "txid unchanged");
    println!("  malleated Tx_lock txid {mal_id}");
    println!(
        "  malleated scriptSig {}",
        hex::encode(mal.vin[0].script_sig.as_bytes())
    );
    let mempool = a.send(&mal).await;
    println!(
        "  sendrawtransaction(malleated Tx_lock): {}",
        show(&mempool)
    );
    let block = a.mine_direct(&[&mal]).await?;
    let tip = synced(a, b).await?;
    ensure!(tip == block, "tip {tip} != generated {block}");
    let (onchain, in_block, _) = a.mined(&mal_id).await?;
    ensure!(
        in_block == block && onchain.vin[0].script_sig == mal.vin[0].script_sig,
        "not mined as sent"
    );
    println!("  malleated Tx_lock mined in block {block} (node B agrees)");
    let lock_op = OutPoint::new(onchain.txid(), 0);

    // The presigned Tx_cancel is now useless: its input does not exist.
    println!(
        "  sendrawtransaction(canonical Tx_lock): {}",
        show(&a.send(&canon).await)
    );
    let c = a.send(&tx_cancel).await;
    println!("  sendrawtransaction(presigned Tx_cancel): {}", show(&c));
    ensure!(c.is_err(), "the presigned Tx_cancel was accepted");
    let h0 = a.height().await?;
    let cb = a.mine_direct(&[&tx_cancel]).await;
    println!("  generateblock(presigned Tx_cancel): {}", show(&cb));
    ensure!(
        cb.is_err() && a.height().await? == h0,
        "a block with the presigned Tx_cancel was accepted"
    );
    let st = a.call("gettxout", json!([mal_id, 0])).await?;
    ensure!(!st.is_null(), "malleated lock output not unspent");
    println!("  lock output {mal_id}:0 unspent, {} DIVI", st["value"]);

    // The maker alone, via t_late, on the outpoint that exists.
    let mut late = spend(lock_op, LOCK_SATS - FEE, swap.maker_refund_script(), t_late);
    let sig =
        crypto::sign_plain(&late, &swap.lock_redeem, &swap.maker_key).map_err(|e| e.to_string())?;
    late.vin[0].script_sig = lock_scripts::late_sig(&sig, &swap.lock_redeem);
    ensure!(
        lock_scripts::lock_spend_branch(&late, &swap.lock_redeem) == Some(LockSpend::Late),
        "late spend not classified as the late branch"
    );
    let late_id = late.txid().to_hex();
    println!(
        "  late spend {late_id} (lock_time {t_late}, hp2 clock {})",
        now()
    );
    let early = a.send(&late).await;
    println!(
        "  sendrawtransaction(late spend) before t_late: {}",
        show(&early)
    );
    ensure!(early.is_err(), "late spend accepted before t_late");
    let wait = (t_late as u64 + 5).saturating_sub(now());
    println!("  waiting {wait}s for t_late");
    tokio::time::sleep(Duration::from_secs(wait)).await;
    let id = a.send(&late).await.map_err(|e| {
        format!("FINDING: the maker's late spend is not relayable after t_late: {e}")
    })?;
    println!("  sendrawtransaction(late spend) after t_late: ACCEPTED ({id})");
    let lblock = a.mine(1).await?.pop().unwrap_or_default();
    synced(a, b).await?;
    let (_, l_in, conf) = a.mined(&late_id).await?;
    ensure!(
        l_in == lblock && conf >= 1,
        "late spend in {l_in}, expected {lblock}"
    );
    let (_, b_l, _) = b.mined(&late_id).await?;
    ensure!(b_l == lblock, "node B has the late spend in {b_l}");
    ensure!(
        a.call("gettxout", json!([mal_id, 0])).await?.is_null(),
        "lock still unspent"
    );
    println!(
        "  late spend mined in block {lblock} (node B agrees); maker recovered {} sats",
        LOCK_SATS - FEE
    );
    println!("  Test 7: PASS");
    Ok(())
}

// ---------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        println!("\nHARNESS FAILED: {e}");
        std::process::exit(1);
    }
}

async fn run() -> R<()> {
    let dir = std::env::var("C1RT_DIR").unwrap_or("/mnt/storage1/bshuler-xmr/c1-regtest".into());
    let a = Node::open("A", &format!("{dir}/a"))?;
    let b = Node::open("B", &format!("{dir}/b"))?;
    let info = a.call("getinfo", json!([])).await?;
    println!(
        "node A: version {} protocol {}",
        info["version"], info["protocolversion"]
    );
    println!(
        "node B connections: {}",
        b.call("getconnectioncount", json!([])).await?
    );

    let h = a.height().await?;
    if h < 30 {
        a.mine(30 - h).await?;
    }
    synced(&a, &b).await?;
    let mtp = a.mtp().await?;
    println!(
        "height {} mtp {mtp} (CLTV/LIMIT_TRANSFER need mtp >= {CLTV_ACTIVATION_MTP})",
        a.height().await?
    );
    ensure!(mtp >= CLTV_ACTIVATION_MTP, "CLTV not active by MTP");
    println!("wallet balance: {}", a.call("getbalance", json!([])).await?);

    let key = SecretKey::new_random();
    let f = Funder {
        spk: p2pkh_spk(&key),
        key,
    };
    let utxos = f.fund(&a, 3).await?;
    let primes = load_primes();

    let mut verdicts = Vec::new();
    for (label, u, enc) in [
        (
            "a (high-S sigma_J)",
            &utxos[0],
            high_s as fn(&[u8], &[u8]) -> R<Vec<u8>>,
        ),
        ("b (PUSHDATA1 sigma_J)", &utxos[1], pushdata1_sig),
    ] {
        let r = test5(label, &a, &b, &f, u, &primes, enc).await;
        if let Err(e) = &r {
            println!("  Test 5{label}: FAIL: {e}");
        }
        verdicts.push((format!("5{label}"), r.is_ok()));
    }
    let r = test7(&a, &b, &f, &utxos[2], &primes).await;
    if let Err(e) = &r {
        println!("  Test 7: FAIL: {e}");
    }
    verdicts.push(("7".into(), r.is_ok()));

    println!(
        "\nfinal height {} tip {}",
        a.height().await?,
        a.tip().await?
    );
    for (t, ok) in &verdicts {
        println!("Test {t}: {}", if *ok { "PASS" } else { "FAIL" });
    }
    ensure!(verdicts.iter().all(|v| v.1), "a test failed");
    Ok(())
}
