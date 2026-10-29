// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

use crate::error::{codes, Error, RpcError};
use crate::protocol::Params;
use divi_network::SporkManager;
use parking_lot::RwLock;
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// (id, name, default value) for every spork C++ lists, in id order.
/// Defaults match `mapSporkDefaults` in C++ spork.cpp; `None` = no default.
const SPORKS: &[(i32, &str, Option<&str>)] = &[
    (10001, "SPORK_2_SWIFTTX_ENABLED", Some("0")),
    (10002, "SPORK_3_SWIFTTX_BLOCK_FILTERING", Some("0")),
    (10004, "SPORK_5_INSTANTSEND_MAX_VALUE", Some("1000")),
    (
        10007,
        "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT",
        Some("1537971708"),
    ),
    (10008, "SPORK_9_SUPERBLOCKS_ENABLED", Some("4070908800")),
    (
        10009,
        "SPORK_10_MASTERNODE_PAY_UPDATED_NODES",
        Some("4070908800"),
    ),
    (10011, "SPORK_12_RECONSIDER_BLOCKS", Some("0")),
    (10012, "SPORK_13_BLOCK_PAYMENTS", None),
    (10013, "SPORK_14_TX_FEE", None),
    (10014, "SPORK_15_BLOCK_VALUE", None),
    (10015, "SPORK_16_LOTTERY_TICKET_MIN_VALUE", None),
];

/// Sporks that hold a list of values and are never "active" by timestamp.
fn is_multi_value(id: i32) -> bool {
    (10012..=10015).contains(&id)
}

#[derive(Default)]
pub struct SporkRpc {
    manager: RwLock<Option<Arc<SporkManager>>>,
}

impl SporkRpc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_manager(&self, manager: Arc<SporkManager>) {
        *self.manager.write() = Some(manager);
    }

    fn received_value(&self, id: i32) -> Option<String> {
        self.manager
            .read()
            .as_ref()
            .and_then(|m| m.get_spork(id))
            .map(|s| s.value)
    }

    /// C++ `GetSporkValue`: network value, else the default, else empty.
    fn value(&self, id: i32, default: Option<&str>) -> String {
        self.received_value(id)
            .or_else(|| default.map(str::to_string))
            .unwrap_or_default()
    }

    /// C++ `IsSporkActive`.
    fn is_active(&self, id: i32, default: Option<&str>) -> bool {
        if is_multi_value(id) {
            return self.received_value(id).is_some();
        }
        let v = self
            .received_value(id)
            .or_else(|| default.map(str::to_string))
            .unwrap_or_else(|| "4070908800".to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        v.parse::<i64>().map(|t| t < now).unwrap_or(false)
    }

    /// spork "show" | "active" | <name> <value>
    pub fn spork(&self, params: &Params) -> Result<Value, Error> {
        let usage = || -> Error {
            RpcError::new(
                codes::MISC_ERROR,
                "spork <name> [<value>]\n<name> is the corresponding spork name, or 'show' to show all current spork settings, active to show which sporks are active<value> is a epoch datetime to enable or disable spork",
            )
            .into()
        };
        // params[n].get_str(): json_spirit takes only a string (rpcmisc.cpp:280-301)
        let arg = |i: usize| crate::masternode::str_arg(params, i);
        match params.len() {
            1 => match arg(0)? {
                Some("show") => Ok(Value::Object(
                    SPORKS
                        .iter()
                        .map(|(id, name, d)| (name.to_string(), json!(self.value(*id, *d))))
                        .collect::<Map<_, _>>(),
                )),
                Some("active") => Ok(Value::Object(
                    SPORKS
                        .iter()
                        .map(|(id, name, d)| (name.to_string(), json!(self.is_active(*id, *d))))
                        .collect::<Map<_, _>>(),
                )),
                _ => Err(usage()),
            },
            2 => {
                let name = arg(0)?.ok_or_else(usage)?;
                if !SPORKS.iter().any(|(_, n, _)| *n == name) {
                    return Ok(json!("Invalid spork name"));
                }
                arg(1)?;
                // Updating a spork needs the network's spork private key.
                Ok(json!("failure"))
            }
            _ => Err(usage()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Params {
        Params::Array(args.iter().map(|a| json!(a)).collect())
    }

    #[test]
    fn show_lists_c_plus_plus_defaults() {
        let v = SporkRpc::new().spork(&p(&["show"])).unwrap();
        assert_eq!(v["SPORK_2_SWIFTTX_ENABLED"], "0");
        assert_eq!(v["SPORK_5_INSTANTSEND_MAX_VALUE"], "1000");
        assert_eq!(v["SPORK_9_SUPERBLOCKS_ENABLED"], "4070908800");
        assert_eq!(v["SPORK_13_BLOCK_PAYMENTS"], "");
        assert_eq!(v.as_object().unwrap().len(), 11);
    }

    #[test]
    fn active_follows_default_timestamps() {
        let v = SporkRpc::new().spork(&p(&["active"])).unwrap();
        assert_eq!(v["SPORK_2_SWIFTTX_ENABLED"], true);
        assert_eq!(v["SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT"], true);
        assert_eq!(v["SPORK_9_SUPERBLOCKS_ENABLED"], false);
        assert_eq!(v["SPORK_13_BLOCK_PAYMENTS"], false);
    }

    /// spork reads its name and value with get_str (rpcmisc.cpp:280-301): another
    /// JSON type is json_spirit's -1 type error; the value is read after the name
    /// is found
    #[test]
    fn spork_name_and_value_must_be_strings() {
        let r = SporkRpc::new();
        let code_message = |params: Vec<Value>| match r.spork(&Params::Array(params)) {
            Err(Error::Rpc(e)) => (e.code, e.message),
            other => panic!("expected an RPC error, got {other:?}"),
        };
        let type_error = |t: &str| (-1, format!("value is type {t}, expected str"));
        assert_eq!(
            code_message(vec![json!("SPORK_2_SWIFTTX_ENABLED"), json!(4070908800u64)]),
            type_error("int")
        );
        assert_eq!(code_message(vec![json!(2), json!("1")]), type_error("int"));
        assert_eq!(code_message(vec![json!(true)]), type_error("bool"));
        assert_eq!(
            r.spork(&Params::Array(vec![json!("NOPE"), json!(1)]))
                .unwrap(),
            "Invalid spork name"
        );
    }

    #[test]
    fn update_paths_match_cpp() {
        let r = SporkRpc::new();
        assert_eq!(r.spork(&p(&["NOPE", "1"])).unwrap(), "Invalid spork name");
        assert_eq!(
            r.spork(&p(&["SPORK_2_SWIFTTX_ENABLED", "1"])).unwrap(),
            "failure"
        );
        assert!(r.spork(&p(&["bogus"])).is_err());
        assert!(r.spork(&p(&[])).is_err());
    }
}
