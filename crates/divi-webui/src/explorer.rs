// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Address validation and chain-index formatting for the built-in Explorer
//! (`#/explorer/address/:addr` -> `GET /api/explorer/address/:addr`).

use divi_electrum::Backend;
use divi_wallet::{Address, AddressType, Network};
use serde_json::{json, Value};

use crate::chainview;

pub const INDEX_HINT: &str =
    "Enable txindex=1 and addressindex=1 in Settings to index arbitrary addresses.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddress {
    pub address: String,
    pub address_type: &'static str,
    pub script_pubkey: String,
}

/// Validate a Base58Check Divi address against the node's active network.
pub fn parse_address(addr: &str, network: Network) -> Result<ParsedAddress, String> {
    let trimmed = addr.trim();
    if trimmed.is_empty() || trimmed.len() > 96 {
        return Err("invalid Divi address".into());
    }
    let decoded = Address::from_base58_for_network(trimmed, network)
        .map_err(|_| format!("{trimmed} is not a valid address on this network"))?;
    let address_type = match decoded.addr_type {
        AddressType::P2PKH => "P2PKH",
        AddressType::P2SH => "P2SH",
    };
    Ok(ParsedAddress {
        address: trimmed.to_string(),
        address_type,
        script_pubkey: decoded.script_pubkey().to_hex(),
    })
}

/// Read an address's balance, unspent coins, and net transaction history from
/// the node's Electrum backend (mempool included).
pub fn read_electrum_address(
    backend: &Backend,
    parsed: &ParsedAddress,
    network: Network,
) -> Result<Value, String> {
    let view = chainview::read(backend, std::slice::from_ref(&parsed.address), network)?;
    let utxos: Vec<Value> = view
        .coins
        .iter()
        .map(|c| {
            json!({
                "txid": c.txid,
                "vout": c.vout,
                "satoshis": c.value,
                "height": c.height,
            })
        })
        .collect();
    let history: Vec<Value> = view
        .history
        .iter()
        .map(|l| {
            json!({
                "txid": l.txid,
                "height": l.height,
                "satoshis": l.satoshis,
            })
        })
        .collect();
    Ok(json!({
        "address": parsed.address,
        "address_type": parsed.address_type,
        "script_pubkey": parsed.script_pubkey,
        "valid": true,
        "indexed": true,
        "confirmed_sat": view.confirmed,
        "pending_sat": view.pending,
        "utxos": utxos,
        "history": history,
    }))
}

/// Format an address lookup obtained from JSON-RPC `getaddressbalance`,
/// `getaddressutxos`, and `getaddresstxids` when the Electrum backend handle is
/// absent.
pub fn format_rpc_address(
    parsed: &ParsedAddress,
    balance: &Value,
    utxos_val: Option<&Value>,
    txids_val: Option<&Value>,
) -> Value {
    let confirmed_sat = balance.get("balance").and_then(Value::as_i64).unwrap_or(0);
    let received_sat = balance.get("received").and_then(Value::as_i64).unwrap_or(0);
    let utxos: Vec<Value> = utxos_val
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|u| {
                    json!({
                        "txid": u.get("txid").and_then(Value::as_str).unwrap_or(""),
                        "vout": u.get("outputIndex").or_else(|| u.get("vout")).and_then(Value::as_u64).unwrap_or(0),
                        "satoshis": u.get("satoshis").and_then(Value::as_i64).unwrap_or(0),
                        "height": u.get("height").and_then(Value::as_u64),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let history: Vec<Value> = txids_val
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .rev()
                .take(chainview::HISTORY)
                .filter_map(Value::as_str)
                .map(|txid| {
                    json!({
                        "txid": txid,
                        "height": Value::Null,
                        "satoshis": Value::Null,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "address": parsed.address,
        "address_type": parsed.address_type,
        "script_pubkey": parsed.script_pubkey,
        "valid": true,
        "indexed": true,
        "confirmed_sat": confirmed_sat,
        "received_sat": received_sat,
        "pending_sat": 0,
        "utxos": utxos,
        "history": history,
    })
}

/// Response when the address is valid on this network, but `txindex=1` and
/// `addressindex=1` are not enabled on the node.
pub fn unindexed_response(parsed: &ParsedAddress) -> Value {
    json!({
        "address": parsed.address,
        "address_type": parsed.address_type,
        "script_pubkey": parsed.script_pubkey,
        "valid": true,
        "indexed": false,
        "hint": INDEX_HINT,
    })
}

/// Whether an Electrum or RPC error indicates that address or transaction
/// indexing is switched off rather than a malformed request.
pub fn is_index_disabled_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("address index")
        || lower.contains("addressindex")
        || lower.contains("transaction index")
        || lower.contains("txindex")
        || lower.contains("no information available for address")
}

#[cfg(test)]
mod tests {
    use super::*;
    use divi_primitives::hash::Hash160;

    #[test]
    fn validates_p2pkh_and_p2sh_per_network() {
        let h = Hash160::from_bytes([0x42u8; 20]);
        let main_p2pkh = Address::from_pubkey_hash(h, Network::Mainnet).to_string();
        let main_p2sh = Address::p2sh(h, Network::Mainnet).to_string();
        let reg_p2pkh = Address::from_pubkey_hash(h, Network::Regtest).to_string();

        let p1 = parse_address(&main_p2pkh, Network::Mainnet).unwrap();
        assert_eq!(p1.address_type, "P2PKH");
        assert!(!p1.script_pubkey.is_empty());

        let p2 = parse_address(&main_p2sh, Network::Mainnet).unwrap();
        assert_eq!(p2.address_type, "P2SH");

        // Wrong network and malformed strings are rejected
        assert!(parse_address(&main_p2pkh, Network::Regtest).is_err());
        assert!(parse_address(&reg_p2pkh, Network::Mainnet).is_err());
        assert!(parse_address("not-a-divi-address", Network::Regtest).is_err());
        assert!(parse_address("", Network::Regtest).is_err());
    }

    #[test]
    fn unindexed_and_rpc_fallback_shapes_match_contract() {
        let h = Hash160::from_bytes([0x11u8; 20]);
        let reg = Address::from_pubkey_hash(h, Network::Regtest).to_string();
        let parsed = parse_address(&reg, Network::Regtest).unwrap();

        let off = unindexed_response(&parsed);
        assert_eq!(off["valid"], true);
        assert_eq!(off["indexed"], false);
        assert_eq!(off["hint"], INDEX_HINT);

        let rpc_bal = json!({ "balance": 250_000_000i64, "received": 500_000_000i64 });
        let rpc_utxos = json!([
            { "txid": "aa".repeat(32), "outputIndex": 1, "satoshis": 250_000_000i64, "height": 12 }
        ]);
        let rpc_txids = json!(["bb".repeat(32), "aa".repeat(32)]);
        let on = format_rpc_address(&parsed, &rpc_bal, Some(&rpc_utxos), Some(&rpc_txids));
        assert_eq!(on["valid"], true);
        assert_eq!(on["indexed"], true);
        assert_eq!(on["confirmed_sat"], 250_000_000i64);
        assert_eq!(on["pending_sat"], 0);
        assert_eq!(on["utxos"].as_array().unwrap().len(), 1);
        assert_eq!(on["utxos"][0]["vout"], 1);
        assert_eq!(on["history"].as_array().unwrap().len(), 2);
        // Newest txid first
        assert_eq!(on["history"][0]["txid"], "aa".repeat(32));
    }

    #[test]
    fn is_index_disabled_error_matching() {
        assert!(is_index_disabled_error(
            "Address index is off: enable addressindex=1"
        ));
        assert!(is_index_disabled_error("Transaction index not enabled"));
        assert!(is_index_disabled_error(
            "No information available for address"
        ));
        assert!(!is_index_disabled_error("Invalid parameters"));
        assert!(!is_index_disabled_error("Connection refused"));
    }
}
