// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Zcash testnet transparent-HTLC `ChainBackend` for the DIVI swap engine.
//!
//! Wired onto `lightwalletd`'s `CompactTxStreamer` gRPC service ([`grpc`]) — step 0's chosen
//! primary API (see `- decisions:` in `docs/plans/swap-poc/status/zec.md`). Transaction
//! building, the ZIP-244 signature digest and script self-verification live in [`tx`];
//! t-address encoding lives in [`address`].

pub mod address;
pub mod grpc;
pub mod tx;

use async_trait::async_trait;
use secp256k1::{All, Secp256k1, SecretKey};

use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, LockedOutput, Outpoint, SignedTx, SpendInfo,
    SwapError, Txid,
};

use address::TransparentAddress;
use grpc::{ClientError, CompactBlock, LightwalletdClient};

pub use grpc::RetryPolicy;

type Result<T> = std::result::Result<T, SwapError>;

/// The only public testnet lightwalletd endpoint confirmed reachable from hp2 as of step 0
/// (TLS + ALPN h2 handshake succeeds; used by default by Zecwallet-lite's testnet preset).
/// No working fallback has been found yet — see `- needs:` in `docs/plans/swap-poc/status/zec.md`.
pub const TESTNET_LIGHTWALLETD: &str = "https://testnet.zec.rocks:443";

/// Blocks scanned per `find_spend` call (mirrors the BTC lane's `MAX_SCAN_BLOCKS`): we have
/// no "find the spend of this outpoint" index on this API, only block scanning.
const MAX_SCAN_BLOCKS: u64 = 200;

/// How the zat/byte rate is chosen.
#[derive(Debug, Clone, Copy)]
pub enum FeePolicy {
    /// Always this rate.
    Fixed(u64),
}

impl Default for FeePolicy {
    fn default() -> Self {
        FeePolicy::Fixed(2)
    }
}

impl FeePolicy {
    fn zats_per_byte(&self) -> u64 {
        match self {
            FeePolicy::Fixed(r) => (*r).max(1),
        }
    }
}

/// Zcash testnet transparent [`ChainBackend`].
pub struct ZecBackend {
    client: LightwalletdClient,
    secp: Secp256k1<All>,
    key: SecretKey,
    pubkey: [u8; 33],
    address: TransparentAddress,
    fees: FeePolicy,
}

impl std::fmt::Debug for ZecBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZecBackend")
            .field("address", &self.address.encode())
            .finish_non_exhaustive()
    }
}

impl ZecBackend {
    /// `endpoints`: lightwalletd gRPC base URIs (`https://host:port`), primary first.
    pub fn new(
        endpoints: Vec<String>,
        key: SecretKey,
        fees: FeePolicy,
        retry: RetryPolicy,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let pubkey = key.public_key(&secp).serialize();
        let address = TransparentAddress::p2pkh(&pubkey);
        Ok(Self {
            client: LightwalletdClient::new(endpoints, retry)?,
            secp,
            key,
            pubkey,
            address,
            fees,
        })
    }

    /// [`TESTNET_LIGHTWALLETD`], the step-0 default.
    pub fn testnet(key: SecretKey, fees: FeePolicy) -> Result<Self> {
        Self::new(
            vec![TESTNET_LIGHTWALLETD.to_string()],
            key,
            fees,
            RetryPolicy::default(),
        )
    }

    /// The key's P2PKH `tm…` address (where funding coins live and spends land).
    pub fn address(&self) -> &TransparentAddress {
        &self.address
    }

    /// Confirmed balance (sum of `GetAddressUtxos`) in zatoshi.
    pub async fn balance_zatoshi(&self) -> Result<u64> {
        let utxos = self
            .client
            .address_utxos(&self.address.encode())
            .await
            .map_err(SwapError::from)?;
        Ok(utxos.iter().map(|u| u.value_zat as u64).sum())
    }

    /// Read fresh from `GetLightdInfo` every call — never hard-coded, per the brief (a
    /// network upgrade changes it without warning).
    async fn consensus_branch_id(&self) -> Result<u32> {
        let info = self.client.lightd_info().await.map_err(SwapError::from)?;
        u32::from_str_radix(info.consensus_branch_id.trim(), 16).map_err(|e| {
            SwapError::Other(format!(
                "bad consensusBranchId {:?}: {e}",
                info.consensus_branch_id
            ))
        })
    }

    fn to_signed(built: &tx::ZecTx) -> SignedTx {
        SignedTx {
            txid: Txid(built.txid()),
            raw: built.serialize(),
        }
    }

    fn txid32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(bytes)
            .map_err(|_| SwapError::Other(format!("{what} is {} bytes, want 32", bytes.len())))
    }
}

/// Map a lightwalletd/zcashd reject reason to the engine's taxonomy (zcashd shares its
/// script/mempool rejection wording with DIVI and Bitcoin Core).
fn classify_broadcast_error(message: &str) -> SwapError {
    let m = message.to_ascii_lowercase();
    if m.contains("non-final")
        || m.contains("locktime requirement not satisfied")
        || m.contains("non-mandatory-script-verify-flag (locktime")
    {
        SwapError::Premature(message.trim().to_string())
    } else {
        SwapError::Rejected(message.trim().to_string())
    }
}

/// Whether a reject reason means "the chain already has this exact transaction" — i.e. a
/// rebroadcast of a tx `broadcast()` itself already sent is not a failure. There's nothing
/// to cross-check the error against a different txid with (unlike e.g. an EVM nonce
/// collision): we only ever submit the one `signed_tx.raw` we just built, so a node telling
/// us it already has "the transaction" can only mean that same tx.
fn is_already_known(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("already in block chain")
        || m.contains("already in the block chain")
        || m.contains("txn-already-in-mempool")
        || m.contains("txn-already-known")
        || m.contains("outputs already in utxo set")
        // Zebra's wording (not zcashd's) for a tx it already holds in its mempool or has
        // mined: a live happy-forward run's taker rebroadcast its own already-mined ZEC
        // lock and got "already exists in mempool" back, which the CLI treated as fatal
        // before this fix; "committed to the best chain" is the equivalent once it's mined.
        || m.contains("already exists in mempool")
        || m.contains("transaction was committed to the best chain")
}

/// If `block` has a `CompactTx` spending `want_txid:want_vout`, (spender txid, input index).
fn spend_in_block(
    block: &CompactBlock,
    want_txid: &[u8; 32],
    want_vout: u32,
) -> Option<([u8; 32], u32)> {
    for t in &block.vtx {
        for (i, vin) in t.vin.iter().enumerate() {
            if vin.prevout_txid == want_txid && vin.prevout_index == want_vout {
                let txid = ZecBackend::txid32(&t.txid, "CompactTx.txid").ok()?;
                return Some((txid, i as u32));
            }
        }
    }
    None
}

#[allow(clippy::double_must_use)]
#[async_trait]
impl ChainBackend for ZecBackend {
    fn chain(&self) -> Chain {
        Chain::Zec
    }

    fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }

    async fn tip_height(&self) -> Result<u64> {
        Ok(self
            .client
            .latest_block()
            .await
            .map_err(SwapError::from)?
            .height)
    }

    async fn median_time_past(&self) -> Result<u32> {
        let tip = self.tip_height().await?;
        let start = tip.saturating_sub(10);
        let blocks = self
            .client
            .block_range(start, tip)
            .await
            .map_err(SwapError::from)?;
        let mut times: Vec<u32> = blocks.iter().map(|b| b.time).collect();
        if times.is_empty() {
            return Err(SwapError::Other(
                "lightwalletd returned no blocks for median-time-past".into(),
            ));
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        let branch_id = self.consensus_branch_id().await?;
        let utxos = self
            .client
            .address_utxos(&self.address.encode())
            .await
            .map_err(SwapError::from)?;
        let coins = utxos
            .into_iter()
            .map(|u| {
                Ok(tx::Coin {
                    outpoint: tx::OutPoint {
                        txid: Self::txid32(&u.txid, "GetAddressUtxosReply.txid")?,
                        n: u.index as u32,
                    },
                    value: u.value_zat as u64,
                    script_pubkey: u.script,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let built = tx::build_funding_tx(
            &self.secp,
            &self.key,
            &self.pubkey,
            &coins,
            htlc,
            amount.to_sat(),
            branch_id,
            self.fees.zats_per_byte(),
        )?;
        let signed = Self::to_signed(&built.tx);
        Ok(Funding {
            outpoint: Outpoint {
                txid: signed.txid,
                vout: built.htlc_vout,
            },
            tx: signed,
            amount,
        })
    }

    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        let branch_id = self.consensus_branch_id().await?;
        let outpoint = tx::OutPoint {
            txid: at.txid.0,
            n: at.vout,
        };
        let built = tx::build_spend_tx(
            &self.secp,
            &self.key,
            &self.pubkey,
            htlc,
            outpoint,
            amount.to_sat(),
            tx::Spend::Claim(preimage),
            branch_id,
            self.fees.zats_per_byte(),
        )?;
        Ok(Self::to_signed(&built))
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        let branch_id = self.consensus_branch_id().await?;
        let outpoint = tx::OutPoint {
            txid: at.txid.0,
            n: at.vout,
        };
        let built = tx::build_spend_tx(
            &self.secp,
            &self.key,
            &self.pubkey,
            htlc,
            outpoint,
            amount.to_sat(),
            tx::Spend::Refund,
            branch_id,
            self.fees.zats_per_byte(),
        )?;
        Ok(Self::to_signed(&built))
    }

    async fn broadcast(&self, signed_tx: &SignedTx) -> Result<Txid> {
        match self.client.send_transaction(&signed_tx.raw).await {
            Ok(resp) if resp.error_code == 0 => Ok(signed_tx.txid),
            Ok(resp) => {
                if is_already_known(&resp.error_message) {
                    return Ok(signed_tx.txid);
                }
                Err(classify_broadcast_error(&resp.error_message))
            }
            Err(ClientError::Rejected(m)) => {
                if is_already_known(&m) {
                    return Ok(signed_tx.txid);
                }
                Err(classify_broadcast_error(&m))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        let Some(raw) = self
            .client
            .get_transaction(&txid.0)
            .await
            .map_err(SwapError::from)?
        else {
            return Ok(None);
        };
        // height 0 = mempool; u64::MAX = mined on a fork that isn't the main chain (lightwalletd
        // `RawTransaction.height` doc). Neither is a main-chain confirmation yet.
        if raw.height == 0 || raw.height == u64::MAX {
            return Ok(Some(0));
        }
        let tip = self.tip_height().await?;
        Ok(Some((tip.saturating_sub(raw.height) + 1) as u32))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let Some(raw) = self
            .client
            .get_transaction(&at.txid.0)
            .await
            .map_err(SwapError::from)?
        else {
            return Ok(None);
        };
        let parsed = tx::ParsedTx::parse(&raw.data)?;
        let Some(out) = parsed.vout.get(at.vout as usize) else {
            return Ok(None);
        };
        let want = address::htlc_script_pubkey(&htlc.redeem_script());
        if out.script_pubkey != want {
            return Ok(None);
        }
        let confirmations = if raw.height == 0 || raw.height == u64::MAX {
            0
        } else {
            let tip = self.tip_height().await?;
            (tip.saturating_sub(raw.height) + 1) as u32
        };
        Ok(Some(LockedOutput {
            amount: Amount::from_sat(out.value),
            confirmations,
        }))
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        let tip = self.tip_height().await?;
        if from_height > tip {
            return Ok(None);
        }
        let last = tip.min(from_height.saturating_add(MAX_SCAN_BLOCKS - 1));
        let blocks = self
            .client
            .block_range(from_height, last)
            .await
            .map_err(SwapError::from)?;
        for block in &blocks {
            let Some((spender_txid, input_index)) =
                spend_in_block(block, &outpoint.txid.0, outpoint.vout)
            else {
                continue;
            };
            let Some(full) = self
                .client
                .get_transaction(&spender_txid)
                .await
                .map_err(SwapError::from)?
            else {
                continue; // compact block saw it, full tx vanished (reorg); caller retries.
            };
            let parsed = tx::ParsedTx::parse(&full.data)?;
            let Some(input) = parsed.vin.get(input_index as usize) else {
                continue;
            };
            let height = if full.height == 0 || full.height == u64::MAX {
                None
            } else {
                Some(full.height)
            };
            return Ok(Some(SpendInfo {
                txid: Txid(spender_txid),
                input_index,
                height,
                script_sig: input.script_sig.clone(),
                witness: vec![],
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use divi_swap::htlc::new_preimage;

    use super::*;
    use crate::grpc::{CompactTx, CompactTxIn};
    use crate::tx::OutPoint;

    #[test]
    fn refund_rejected_before_locktime() {
        let err = classify_broadcast_error(
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"64: non-final\"}",
        );
        assert!(matches!(err, SwapError::Premature(_)), "{err:?}");
        assert!(err.is_retryable());

        let err2 = classify_broadcast_error("Locktime requirement not satisfied");
        assert!(matches!(err2, SwapError::Premature(_)), "{err2:?}");

        // Other node refusals are not retryable.
        let err3 = classify_broadcast_error("bad-txns-in-belowout");
        assert!(matches!(err3, SwapError::Rejected(_)), "{err3:?}");
        assert!(!err3.is_retryable());

        assert!(is_already_known(
            "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}"
        ));
        assert!(is_already_known(
            "transaction rejected: transaction already exists in mempool"
        ));
        assert!(is_already_known(
            "transaction rejected: any transaction with the same effects will be rejected \
             from the mempool until a chain reset: transaction was committed to the best chain"
        ));
    }

    /// `broadcast()` must treat a rebroadcast of a tx the chain already has as success, not
    /// a fatal error — the exact live failure: a taker's ZEC lock was accepted and mined,
    /// the taker then rebroadcast it (e.g. after a retry/restart) and Zebra's rejection was
    /// treated as fatal, killing the CLI with real coins already moved.
    #[test]
    fn broadcast_idempotent_already_known_errors() {
        // The exact live message (Zebra's NU7 mempool wording), and the equivalent once
        // the same tx has already been mined rather than just sitting in the mempool.
        assert!(is_already_known(
            "transaction rejected: transaction already exists in mempool"
        ));
        assert!(is_already_known(
            "transaction rejected: any transaction with the same effects will be rejected \
             from the mempool until a chain reset: transaction was committed to the best chain"
        ));
        // Case-insensitive, and with a gRPC Status's Display wrapper around the real text
        // (`ClientError::Rejected` stores `tonic::Status::to_string()`, not the bare
        // message).
        assert!(is_already_known(
            "status: InvalidArgument, message: \"Transaction already exists in mempool\", details: [], metadata: MetadataMap { headers: {} }"
        ));
        // zcashd/bitcoind-style reject reasons (legacy JSON-RPC, still possible from a
        // zcashd-era node or a stale test vector).
        assert!(is_already_known("txn-already-known"));
        assert!(is_already_known("txn-already-in-mempool"));
        assert!(is_already_known(
            "sendrawtransaction RPC error: {\"code\":-27,\"message\":\"Transaction already in block chain\"}"
        ));
        assert!(is_already_known("outputs already in utxo set"));

        // A genuine rejection (not already-known) must not be swallowed as success.
        assert!(!is_already_known("bad-txns-in-belowout"));
        assert!(!is_already_known(
            "transaction rejected: ... Unpaid actions is higher than the limit"
        ));
    }

    #[test]
    fn find_spend_reads_scriptsig() {
        const BRANCH_ID: u32 = 0xc2d6_d0b4;
        let (preimage, hash) = new_preimage();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let pk = sk.public_key(&secp).serialize();
        let htlc = HtlcParams {
            hash,
            claim_pubkey: pk,
            refund_pubkey: pk,
            locktime: 1_900_000_000,
        };
        let fund_outpoint = OutPoint {
            txid: [7; 32],
            n: 1,
        };

        // Build a real claim spend so its scriptSig is genuine.
        let spend = tx::build_spend_tx(
            &secp,
            &sk,
            &pk,
            &htlc,
            fund_outpoint,
            20_000,
            tx::Spend::Claim(&preimage),
            BRANCH_ID,
            2,
        )
        .unwrap();
        let spender_txid = spend.txid();

        // The compact block only carries prevout/index, as the real API would.
        let block = CompactBlock {
            height: 500,
            time: 1_900_000_100,
            vtx: vec![CompactTx {
                index: 1,
                txid: spender_txid.to_vec(),
                vin: vec![CompactTxIn {
                    prevout_txid: fund_outpoint.txid.to_vec(),
                    prevout_index: fund_outpoint.n,
                }],
            }],
        };
        let found = spend_in_block(&block, &fund_outpoint.txid, fund_outpoint.n);
        assert_eq!(found, Some((spender_txid, 0)));

        // The full tx (as `GetTransaction` would return it) is what supplies the scriptSig.
        let raw = spend.serialize();
        let parsed = tx::ParsedTx::parse(&raw).unwrap();
        let script_sig = parsed.vin[0].script_sig.clone();
        let info = SpendInfo {
            txid: Txid(spender_txid),
            input_index: 0,
            height: Some(500),
            script_sig,
            witness: vec![],
        };
        assert_eq!(info.extract_preimage(&hash), Some(preimage));

        // An outpoint this spend doesn't touch is not found.
        let other = OutPoint {
            txid: [8; 32],
            n: 0,
        };
        assert_eq!(spend_in_block(&block, &other.txid, other.n), None);
    }

    /// Read-only, against the live testnet API.
    #[tokio::test]
    #[ignore = "needs network access to testnet.zec.rocks"]
    async fn testnet_api_reachable() {
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let backend = ZecBackend::testnet(sk, FeePolicy::default()).unwrap();
        let tip = backend.tip_height().await.unwrap();
        assert!(tip > 0, "tip height {tip}");
        let mtp = backend.median_time_past().await.unwrap();
        assert!(mtp > 1_700_000_000, "median time past {mtp}");
        let info = backend.consensus_branch_id().await.unwrap();
        assert!(info > 0, "consensus branch id {info:#x}");
        println!("testnet.zec.rocks: tip={tip} mtp={mtp} consensus_branch_id={info:#010x}");
    }

    /// Diagnostic only (not part of the acceptance surface): what transaction version is
    /// actually on-chain right now, post-NU6.3/NU7? We only ever build v5; if the network
    /// requires v6 for everything (not just transactions touching the new Ironwood pool),
    /// our transparent-only transactions would be rejected.
    #[tokio::test]
    #[ignore = "diagnostic: needs network access to testnet.zec.rocks"]
    async fn probe_live_tx_version() {
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let backend = ZecBackend::testnet(sk, FeePolicy::default()).unwrap();
        let tip = backend.client.latest_block().await.unwrap().height;
        let blocks = backend
            .client
            .block_range(tip.saturating_sub(2000), tip)
            .await
            .unwrap();
        let mut seen = 0;
        for b in &blocks {
            for t in &b.vtx {
                let txid: [u8; 32] = t.txid.clone().try_into().unwrap();
                if let Some(raw) = backend.client.get_transaction(&txid).await.unwrap() {
                    let version_bytes = u32::from_le_bytes(raw.data[0..4].try_into().unwrap());
                    println!(
                        "height={} index={} txid={} version_bytes={version_bytes:#010x} (version {}) len={} vin_in_compact={} raw_head={}",
                        b.height,
                        t.index,
                        hex::encode(&t.txid),
                        version_bytes & 0x7fff_ffff,
                        raw.data.len(),
                        t.vin.len(),
                        hex::encode(&raw.data[..raw.data.len().min(80)])
                    );
                    seen += 1;
                    if seen > 30 {
                        return;
                    }
                }
            }
        }
        println!("total txs seen across scanned range: {seen}");
    }

    #[cfg(feature = "live")]
    mod live {
        use std::time::Duration;

        use divi_swap::htlc::new_preimage;
        use divi_swap::{Amount, ChainBackend, HtlcParams, SignedTx, SwapError, Txid};

        use crate::{FeePolicy, ZecBackend};

        const HTLC_ZATOSHI: u64 = 20_000;
        const REFUND_AHEAD_OF_MTP: u32 = 2 * 3600;

        fn key_from_env() -> secp256k1::SecretKey {
            let hex = std::env::var("SWAP_ZEC_TEST_KEY_HEX")
                .expect("SWAP_ZEC_TEST_KEY_HEX must hold a 32-byte hex secp256k1 key");
            secp256k1::SecretKey::from_slice(&hex::decode(hex.trim()).unwrap()).unwrap()
        }

        async fn wait_confirmed(b: &ZecBackend, txid: &Txid, what: &str) {
            for _ in 0..240 {
                if matches!(b.confirmations(txid).await, Ok(Some(c)) if c >= 1) {
                    println!("{what} confirmed: {}", txid.to_rpc_hex());
                    return;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            panic!("{what} {} not confirmed after 2h", txid.to_rpc_hex());
        }

        async fn broadcast(b: &ZecBackend, tx: &SignedTx, what: &str) {
            let id = b.broadcast(tx).await.unwrap();
            assert_eq!(id, tx.txid);
            println!("{what} broadcast: {}", id.to_rpc_hex());
        }

        /// Fund two HTLCs on Zcash testnet with the taker-zec key, claim one, refund the
        /// other once MTP passes a locktime 2h ahead of the MTP at start. Takes about 3h.
        #[tokio::test]
        #[ignore = "needs a funded testnet t-address (SWAP_ZEC_TEST_KEY_HEX) and ~3 h"]
        async fn live_fund_claim_refund() {
            let key = key_from_env();
            let b = ZecBackend::testnet(key, FeePolicy::default()).unwrap();
            println!("address {} on testnet", b.address().encode());

            let locktime = b.median_time_past().await.unwrap() + REFUND_AHEAD_OF_MTP;
            let mk = |hash: [u8; 32]| HtlcParams {
                hash,
                claim_pubkey: b.pubkey(),
                refund_pubkey: b.pubkey(),
                locktime,
            };
            let (pre_claim, hash_claim) = new_preimage();
            let (_, hash_refund) = new_preimage();
            let h_claim = mk(hash_claim);
            let h_refund = mk(hash_refund);
            let amount = Amount::from_sat(HTLC_ZATOSHI);

            let f1 = b.build_funding(&h_claim, amount).await.unwrap();
            broadcast(&b, &f1.tx, "fund(claim)").await;
            wait_confirmed(&b, &f1.tx.txid, "fund(claim)").await;
            let f2 = b.build_funding(&h_refund, amount).await.unwrap();
            broadcast(&b, &f2.tx, "fund(refund)").await;
            wait_confirmed(&b, &f2.tx.txid, "fund(refund)").await;
            println!("live_fund_txid: {}", f1.tx.txid.to_rpc_hex());
            println!("live_fund2_txid: {}", f2.tx.txid.to_rpc_hex());

            let locked = b
                .htlc_output(&h_claim, &f1.outpoint)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(locked.amount, amount);

            let claim = b
                .build_claim(&h_claim, &f1.outpoint, amount, &pre_claim)
                .await
                .unwrap();
            broadcast(&b, &claim, "claim").await;
            wait_confirmed(&b, &claim.txid, "claim").await;
            println!("live_claim_txid: {}", claim.txid.to_rpc_hex());
            let spend = b.find_spend(&f1.outpoint, 0).await.unwrap().unwrap();
            assert_eq!(spend.txid, claim.txid);
            assert_eq!(spend.extract_preimage(&h_claim.hash), Some(pre_claim));

            let refund = b
                .build_refund(&h_refund, &f2.outpoint, amount)
                .await
                .unwrap();
            loop {
                match b.broadcast(&refund).await {
                    Ok(id) => {
                        println!("refund broadcast: {}", id.to_rpc_hex());
                        break;
                    }
                    Err(SwapError::Premature(_)) | Err(SwapError::Transient(_)) => {
                        tokio::time::sleep(Duration::from_secs(120)).await;
                    }
                    Err(e) => panic!("refund rejected: {e}"),
                }
            }
            wait_confirmed(&b, &refund.txid, "refund").await;
            println!("live_refund_txid: {}", refund.txid.to_rpc_hex());
        }
    }
}
