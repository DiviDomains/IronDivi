//! Replays a diag bundle (A13): the block or transaction irondivid kept
//! under diag/invalid, diag/rejected-tx or diag/own-invalid.
//!
//!   irondivi-replay <bundle dir>                       context-free checks
//!   irondivi-replay <bundle dir> <db copy> [testnet]   plus accept_block on
//!                                                      a COPY of the chain
//!
//! Never point it at a live node's database: accept_block writes to it.
//! The context-free checks are the transaction checks every block and
//! mempool entry passes; accept_block runs the node's full block path
//! against the copy's tip, which may differ from the tip at the time.

use std::path::Path;
use std::sync::Arc;

use divi_primitives::constants::MAX_MONEY;
use divi_primitives::{deserialize, Block, Transaction};
use divi_storage::{check_transaction, Chain, ChainDatabase, ChainParams, NetworkType};

fn read_hex(path: &Path) -> Option<Vec<u8>> {
    let text = std::fs::read_to_string(path).ok()?;
    match hex::decode(text.trim()) {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("{}: not hex: {}", path.display(), e);
            std::process::exit(2);
        }
    }
}

fn check_txs(txs: &[Transaction]) -> bool {
    let mut ok = true;
    for (i, tx) in txs.iter().enumerate() {
        match check_transaction(tx, MAX_MONEY) {
            Ok(()) => println!("tx {} {}: context-free checks pass", i, tx.txid()),
            Err(e) => {
                ok = false;
                println!("tx {} {}: FAILS context-free checks: {}", i, tx.txid(), e)
            }
        }
    }
    ok
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 2 {
        eprintln!("usage: irondivi-replay <bundle dir> [<db copy> [testnet]]");
        std::process::exit(2);
    }
    let dir = Path::new(&a[1]);
    if let Ok(state) = std::fs::read_to_string(dir.join("state.txt")) {
        print!("{}", state);
    }
    if let Some(bytes) = read_hex(&dir.join("block.hex")) {
        let block: Block = match deserialize(&bytes) {
            Ok(b) => b,
            Err(e) => {
                println!("block.hex does not decode: {}", e);
                std::process::exit(1);
            }
        };
        println!(
            "block {} with {} transactions",
            block.hash(),
            block.transactions.len()
        );
        let ok = check_txs(&block.transactions);
        if let Some(db_path) = a.get(2) {
            let net = match a.get(3).map(|s| s.as_str()) {
                Some("testnet") => NetworkType::Testnet,
                _ => NetworkType::Mainnet,
            };
            let db = Arc::new(ChainDatabase::open(db_path).expect("open the db copy"));
            let chain = Chain::new(
                db,
                ChainParams::for_network(net, divi_primitives::ChainMode::Divi),
            )
            .expect("chain");
            match chain.accept_block(block) {
                Ok(r) => println!("accept_block: accepted {:?}", r),
                Err(e) => {
                    println!("accept_block: refused: {}", e);
                    std::process::exit(1);
                }
            }
        }
        std::process::exit(if ok { 0 } else { 1 });
    }
    if let Some(bytes) = read_hex(&dir.join("tx.hex")) {
        let tx: Transaction = match deserialize(&bytes) {
            Ok(t) => t,
            Err(e) => {
                println!("tx.hex does not decode: {}", e);
                std::process::exit(1);
            }
        };
        let ok = check_txs(std::slice::from_ref(&tx));
        std::process::exit(if ok { 0 } else { 1 });
    }
    eprintln!("{}: no block.hex or tx.hex", dir.display());
    std::process::exit(2);
}
