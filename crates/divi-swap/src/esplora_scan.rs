// SPDX-License-Identifier: AGPL-3.0-only

//! Evidence used by the BTC/LTC Esplora fallback. Height lookups may observe different
//! tips. Hash-keyed metadata and transaction pages must describe the named immutable
//! block; `tx_count` and the ordered 25-entry pages must enumerate its transactions and
//! every transparent input faithfully. These are adapter assumptions, not Merkle proofs
//! or header consensus validation.

use crate::{Result, ScanMark, SwapError};
use serde_json::Value;
use std::collections::HashSet;

fn invalid(reason: &str) -> SwapError {
    SwapError::Transient(format!("Esplora spend scan: {reason}"))
}

fn hash(v: &Value) -> Result<&str> {
    v.as_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| invalid("missing or malformed hash"))
}

pub fn transaction_count(
    meta: &Value,
    mark: &ScanMark,
    previous: Option<&ScanMark>,
) -> Result<u32> {
    if hash(&meta["id"])? != mark.hash || meta["height"].as_u64() != Some(mark.height) {
        return Err(invalid("block identity differs from height lookup"));
    }
    if mark.height != 0 {
        let parent = hash(&meta["previousblockhash"])?;
        if parent == mark.hash
            || previous
                .is_some_and(|p| p.hash != parent || p.height.checked_add(1) != Some(mark.height))
        {
            return Err(invalid("block does not extend previous scanned block"));
        }
    }
    // A resource ceiling, not a consensus limit. An unsupported block is unread, not empty.
    meta["tx_count"]
        .as_u64()
        .filter(|n| (1..=100_000).contains(n))
        .map(|n| n as u32)
        .ok_or_else(|| invalid("missing or unsupported transaction count"))
}

pub fn checked_page<'a>(
    page: &'a Value,
    mark: &ScanMark,
    start: u32,
    count: u32,
    seen: &mut HashSet<String>,
) -> Result<&'a [Value]> {
    let txs = page
        .as_array()
        .ok_or_else(|| invalid("transaction page is not an array"))?;
    if start >= count || txs.len() != (count - start).min(25) as usize {
        return Err(invalid(
            "transaction page length disagrees with block count",
        ));
    }
    for (offset, tx) in txs.iter().enumerate() {
        if !seen.insert(hash(&tx["txid"])?.to_owned()) {
            return Err(invalid("duplicate transaction in block pages"));
        }
        if let Some(status) = tx.get("status") {
            if status["confirmed"].as_bool() != Some(true)
                || status["block_height"].as_u64() != Some(mark.height)
                || hash(&status["block_hash"])? != mark.hash
            {
                return Err(invalid("transaction status disagrees with block"));
            }
        }
        let inputs = tx["vin"]
            .as_array()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| invalid("missing transaction inputs"))?;
        for vin in inputs {
            if vin["is_coinbase"].as_bool() == Some(true) {
                if start != 0 || offset != 0 || inputs.len() != 1 {
                    return Err(invalid("misplaced coinbase input"));
                }
                // A coinbase has no spendable prevout.
                if vin["txid"].is_null() && vin["vout"].is_null() {
                    continue;
                }
            }
            hash(&vin["txid"])?;
            if !vin["vout"].as_u64().is_some_and(|n| n <= u32::MAX as u64) {
                return Err(invalid("missing or malformed input vout"));
            }
        }
    }
    Ok(txs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn changing_tip_must_still_extend_the_scanned_prefix() {
        let prev = ScanMark {
            height: 6,
            hash: "11".repeat(32),
        };
        let next = ScanMark {
            height: 7,
            hash: "22".repeat(32),
        };
        let mut header =
            json!({"height":7,"id":next.hash,"tx_count":1,"previousblockhash":prev.hash});
        assert_eq!(transaction_count(&header, &next, Some(&prev)).unwrap(), 1);
        header["previousblockhash"] = json!("33".repeat(32));
        assert!(transaction_count(&header, &next, Some(&prev)).is_err());
    }

    #[test]
    fn a_missing_or_unreadable_page_is_not_a_scanned_block() {
        let mark = ScanMark {
            height: 7,
            hash: "22".repeat(32),
        };
        let tx = json!({"txid":"11".repeat(32),"vin":[{"txid":"33".repeat(32),"vout":2}]});
        let mut seen = HashSet::new();
        for (page, count) in [
            (Value::Null, 1),
            (json!({}), 1),
            (json!([]), 1),
            (json!([tx]), 26),
            (json!([{"txid":"11".repeat(32)}]), 1),
            (json!([{"txid":"11".repeat(32),"vin":[{}]}]), 1),
        ] {
            assert!(checked_page(&page, &mark, 0, count, &mut HashSet::new()).is_err());
        }
        let page = json!([tx]);
        assert_eq!(
            checked_page(&page, &mark, 25, 26, &mut seen).unwrap().len(),
            1
        );
        assert!(checked_page(&page, &mark, 25, 26, &mut seen).is_err());
    }
}
