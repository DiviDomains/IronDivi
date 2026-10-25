//! The treasury and lottery checks over the superblocks of a real chain.
//!
//! Ignored: it needs a chain that is not in the tree. Nothing is written to
//! that chain. Run by hand, with the network and one source:
//!
//! ```sh
//! # an irondivid chain database, opened read-only (a running node's too)
//! SB_REAL_NET=testnet SB_REAL_DB=~/node/chainstate \
//!     cargo test -p divi-storage --test real_superblocks -- --ignored --nocapture
//! # or lines "<height> <block hex> <winner scripts at height - 1, hex, comma
//! # separated, or ->" written from divid by scripts/superblocks/real-dump.py
//! SB_REAL_NET=mainnet SB_REAL_DUMP=superblocks.txt cargo test ...
//! ```
//!
//! The winner scripts must be the exact scripts: divid's getlotteryblockwinners
//! shows a P2PK winner by its address, as it shows a P2PKH one, and
//! real-dump.py tells the two apart by the cycle's coinstakes.
//!
//! For every treasury block it runs the old treasury check (the last output
//! to each script must have the amount) and the one in `check_treasury_payments`
//! (Divi Core's IsValidTreasuryPayment: some output of exactly the amount to
//! exactly the script), and lists every height where the two disagree. For
//! every lottery block it runs `check_lottery_payments` with the winners of the
//! block before. It fails if a real block is refused.

use std::io::BufRead;

use divi_consensus::treasury::{self, SuperblockPayout};
use divi_primitives::block::Block;
use divi_primitives::script::Script;
use divi_primitives::{LotteryCoinstake, LotteryWinners};
use divi_storage::{
    check_lottery_payments, check_treasury_payments, treasury_payments_due, ChainDatabase,
    NetworkType,
};

/// One superblock and the winners of the block before it
struct Superblock {
    height: u32,
    block: Block,
    winners: LotteryWinners,
}

/// (treasury start, treasury cycle, lottery start, lottery cycle, halving)
fn params(network: NetworkType) -> (u32, u32, u32, u32, u32) {
    use divi_consensus::lottery;
    match network {
        NetworkType::Mainnet => (
            treasury::mainnet::TREASURY_START_BLOCK,
            treasury::mainnet::TREASURY_CYCLE,
            lottery::mainnet::LOTTERY_START_BLOCK,
            lottery::mainnet::LOTTERY_CYCLE,
            525_600,
        ),
        NetworkType::Testnet => (
            treasury::testnet::TREASURY_START_BLOCK,
            treasury::testnet::TREASURY_CYCLE,
            lottery::testnet::LOTTERY_START_BLOCK,
            lottery::testnet::LOTTERY_CYCLE,
            1_000,
        ),
        NetworkType::Regtest => (
            treasury::regtest::TREASURY_START_BLOCK,
            treasury::regtest::TREASURY_CYCLE,
            lottery::regtest::LOTTERY_START_BLOCK,
            lottery::regtest::LOTTERY_CYCLE,
            100,
        ),
    }
}

fn payout(network: NetworkType, height: u32) -> SuperblockPayout {
    let (ts, tc, ls, lc, _) = params(network);
    treasury::superblock_payout(height, ts, tc, ls, lc)
}

/// The treasury check before it followed IsValidTreasuryPayment: the last
/// output to the treasury script, and the last to the charity script, must
/// each have the amount due
fn old_treasury_check(network: NetworkType, block: &Block, height: u32) -> Result<(), String> {
    let Some(due) = treasury_payments_due(network, height) else {
        return Ok(());
    };
    let coinstake = block
        .transactions
        .get(1)
        .ok_or("Treasury block missing coinstake")?;
    for (name, (script, amount)) in [("treasury", &due.treasury), ("charity", &due.charity)] {
        let last = coinstake
            .vout
            .iter()
            .rfind(|o| o.script_pubkey == *script)
            .map(|o| o.value);
        match last {
            None => return Err(format!("missing {name} payment")),
            Some(v) if v != *amount => {
                return Err(format!("{name}: expected {amount}, got {v}"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn network_from_env() -> NetworkType {
    match std::env::var("SB_REAL_NET").as_deref() {
        Ok("mainnet") => NetworkType::Mainnet,
        Ok("testnet") => NetworkType::Testnet,
        Ok("regtest") => NetworkType::Regtest,
        other => panic!("SB_REAL_NET must be mainnet, testnet or regtest, not {other:?}"),
    }
}

/// Superblocks of an irondivid chain database, read-only. Heights whose body
/// is gone (pruned) are counted, not checked.
fn from_db(network: NetworkType, path: &str, missing: &mut Vec<u32>) -> Vec<Superblock> {
    let db = ChainDatabase::open_read_only(path).expect("open the chain database read-only");
    let best = db.get_best_block().unwrap().expect("a best block");
    let tip = db
        .get_block_index(&best)
        .unwrap()
        .expect("tip index")
        .height;
    println!("{path}: tip {tip}, pruned to {}", db.prune_height());
    let mut out = Vec::new();
    for height in 1..=tip {
        if payout(network, height) == SuperblockPayout::None {
            continue;
        }
        let hash = db
            .get_height_mapping(height)
            .unwrap()
            .expect("height mapping");
        let Some(block) = db.get_block(&hash).ok().flatten() else {
            missing.push(height);
            continue;
        };
        let prev = db
            .get_block_index(&block.header.prev_block)
            .unwrap()
            .expect("previous index");
        out.push(Superblock {
            height,
            block,
            winners: prev.lottery_winners,
        });
    }
    out
}

/// Superblocks from a dump of divid's replies
fn from_dump(path: &str) -> Vec<Superblock> {
    let file = std::fs::File::open(path).expect("open the dump");
    let mut out = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line.unwrap();
        let mut fields = line.split_whitespace();
        let (Some(h), Some(hex_block), Some(scripts)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let height: u32 = h.parse().expect("height");
        let block: Block =
            divi_primitives::serialize::deserialize(&hex::decode(hex_block).unwrap())
                .expect("block");
        let mut winners = LotteryWinners::new(height - 1);
        if scripts != "-" {
            for s in scripts.split(',') {
                winners.coinstakes.push(LotteryCoinstake::new(
                    Default::default(),
                    Script::from_bytes(hex::decode(s).unwrap()),
                ));
            }
        }
        out.push(Superblock {
            height,
            block,
            winners,
        });
    }
    out
}

#[test]
#[ignore = "needs a real chain: SB_REAL_NET and SB_REAL_DB or SB_REAL_DUMP"]
fn real_superblocks() {
    let network = network_from_env();
    let mut missing = Vec::new();
    let blocks = match (std::env::var("SB_REAL_DB"), std::env::var("SB_REAL_DUMP")) {
        (Ok(db), _) => from_db(network, &db, &mut missing),
        (_, Ok(dump)) => from_dump(&dump),
        _ => panic!("set SB_REAL_DB or SB_REAL_DUMP"),
    };
    let (_, _, _, lottery_cycle, halving) = params(network);

    let (mut treasury_n, mut old_refused, mut lottery_n, mut lottery_empty) = (0, 0, 0, 0);
    let (mut disagree, mut refused) = (Vec::new(), Vec::new());
    for sb in &blocks {
        match payout(network, sb.height) {
            SuperblockPayout::Treasury => {
                treasury_n += 1;
                let old = old_treasury_check(network, &sb.block, sb.height);
                let new = check_treasury_payments(network, &sb.block, sb.height);
                if old.is_err() {
                    old_refused += 1;
                }
                if old.is_ok() != new.is_ok() {
                    disagree.push(format!("{}: old {old:?}, new {new:?}", sb.height));
                }
                if let Err(e) = new {
                    refused.push(format!("treasury {}: {e}", sb.height));
                }
            }
            SuperblockPayout::Lottery => {
                lottery_n += 1;
                if sb.winners.coinstakes.is_empty() {
                    lottery_empty += 1;
                }
                // The lottery check is the same before and after
                if let Err(e) = check_lottery_payments(
                    &sb.block,
                    sb.height,
                    &sb.winners,
                    lottery_cycle,
                    halving,
                ) {
                    refused.push(format!("lottery {}: {e}", sb.height));
                }
            }
            SuperblockPayout::None => {}
        }
    }

    let first = blocks.first().map(|b| b.height);
    let last = blocks.last().map(|b| b.height);
    println!("network {network:?}, superblocks checked from {first:?} to {last:?}");
    println!(
        "treasury blocks {treasury_n}: old check refused {old_refused}, new refused {}; disagree {}",
        refused.iter().filter(|r| r.starts_with("treasury")).count(),
        disagree.len()
    );
    println!("lottery blocks {lottery_n} ({lottery_empty} with no winners, which pass)");
    println!(
        "superblocks without a body (pruned): {}{}",
        missing.len(),
        match (missing.first(), missing.last()) {
            (Some(a), Some(b)) => format!(", {a} to {b}"),
            _ => String::new(),
        }
    );
    for d in &disagree {
        println!("DISAGREE {d}");
    }
    for r in &refused {
        println!("REFUSED {r}");
    }
    assert!(!blocks.is_empty(), "no superblock with a body");
    assert!(
        refused.is_empty(),
        "{} real superblocks refused",
        refused.len()
    );
}
