// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! sendrawtransaction refusals as Divi Core 3.0.0's divid gives them
//! (scripts/reject-replies compares them on live nodes): output values the
//! fee total cannot add up.

use divi_crypto::compute_merkle_root;
use divi_primitives::{
    amount::Amount,
    block::Block,
    hash::{Hash160, Hash256},
    script::Script,
    serialize::serialize,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
    ChainMode,
};
use divi_rpc::{Params, Request, RequestId, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use serde_json::{json, Value};
use std::sync::Arc;

const COIN: i64 = 100_000_000;

struct Node {
    chain: Arc<Chain>,
    server: RpcServer,
    _dir: tempfile::TempDir,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let server = RpcServer::new(chain.clone());
    server
        .wallet()
        .set_tx_submit(Arc::new(|tx: Transaction| Ok(tx.txid())));
    Node {
        chain,
        server,
        _dir: dir,
    }
}

impl Node {
    fn send(&self, tx: &Transaction) -> Result<Value, (i32, String)> {
        let r = self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: "sendrawtransaction".to_string(),
            params: Params::Array(vec![json!(hex::encode(serialize(tx)))]),
        });
        match r.error {
            Some(e) => Err((e.code, e.message)),
            None => Ok(r.result.unwrap()),
        }
    }

    /// Mine a block whose coinbase pays 1250 DIVI to a key nobody holds
    fn mine(&self) -> Transaction {
        let tip = self.chain.tip().unwrap();
        let height = tip.height + 1;
        let mut block = Block::default();
        block.header.version = 4;
        block.header.prev_block = tip.hash;
        block.header.time = tip.time + 60;
        block.header.bits = 0x207fffff;
        let mut cb_sig = divi_storage::bip34_height_script(height);
        cb_sig.extend_from_slice(&height.to_le_bytes());
        block.transactions.push(Transaction {
            version: 1,
            vin: vec![TxIn::coinbase(Script::from_bytes(cb_sig))],
            vout: vec![TxOut::new(Amount::from_sat(1250 * COIN), payee())],
            lock_time: 0,
        });
        block.header.merkle_root = compute_merkle_root(&block.transactions);
        let target = Hash256::from_compact(block.header.bits);
        while divi_crypto::compute_block_hash(&block.header) > target {
            block.header.nonce += 1;
        }
        let coinbase = block.transactions[0].clone();
        self.chain.accept_block(block).unwrap();
        self.server.set_height(height);
        coinbase
    }
}

fn payee() -> Script {
    Script::new_p2pkh(Hash160::from_bytes([0x42; 20]).as_bytes())
}

/// An unsigned spend of `input` paying `values` (satoshis)
fn spend(input: OutPoint, values: &[i64]) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn::new(input, Script::new(), 0xffffffff)],
        vout: values
            .iter()
            .map(|v| TxOut::new(Amount::from_sat(*v), payee()))
            .collect(),
        lock_time: 0,
    }
}

/// Once the inputs are known, the fee total reads CTransaction::GetValueOut,
/// which throws for a negative output or a sum past the int64 range: -1 with
/// its message, before the mempool sees the transaction
/// (rpcrawtransaction.cpp:810-826, :877; primitives/transaction.cpp:245-259)
#[test]
fn output_values_the_fee_total_cannot_add_are_refused_as_core() {
    let n = node();
    let coin = OutPoint::new(n.mine().txid(), 0);
    assert_eq!(
        n.send(&spend(coin, &[-1])),
        Err((
            -1,
            "CTransaction::GetValueOut() : value out of range : less than 0".to_string()
        ))
    );
    assert_eq!(
        n.send(&spend(coin, &[COIN, -1])),
        Err((
            -1,
            "CTransaction::GetValueOut() : value out of range : less than 0".to_string()
        ))
    );
    assert_eq!(
        n.send(&spend(coin, &[1 << 62, 1 << 62])),
        Err((
            -1,
            "CTransaction::GetValueOut() : value out of range : wraps the int64_t boundary"
                .to_string()
        ))
    );
    // Unknown inputs are answered first
    let unknown = OutPoint::new(Hash256::from_bytes([0x11; 32]), 0);
    assert_eq!(
        n.send(&spend(unknown, &[-1])),
        Err((-26, "Unknown inputs being spent".to_string()))
    );
    // A single output over the money supply adds up: the mempool refuses it
    // (here the submit stand-in takes it)
    let big = spend(coin, &[1 << 62]);
    assert_eq!(n.send(&big), Ok(json!(big.txid().to_string())));
}
