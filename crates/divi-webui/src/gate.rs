// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! What the web interface lets a signed-in user call. It never hands out
//! keys, it never unlocks the wallet for spending past a short while, and
//! until the wallet is encrypted it only reads and offers to encrypt.

use serde_json::Value;

/// Calls that write keys out; the web interface never makes them
const KEY_EXPORTS: &[&str] = &["dumpprivkey", "dumpwallet", "dumphdinfo"];

/// The longest full unlock the web interface grants, in seconds
pub const MAX_FULL_UNLOCK_SECS: i64 = 600;

/// Calls an unencrypted wallet may still make: reads, and encrypting it
fn reads(method: &str) -> bool {
    const PREFIXES: &[&str] = &["get", "list", "validate", "verify", "decode", "estimate"];
    PREFIXES.iter().any(|p| method.starts_with(p))
        || matches!(method, "help" | "ping" | "encryptwallet")
}

/// Whether the call may go to the daemon, given the wallet's
/// `encryption_status` (None without a wallet)
pub fn check(method: &str, params: &[Value], wallet: Option<&str>) -> Result<(), String> {
    if KEY_EXPORTS.contains(&method) {
        return Err(format!(
            "{method} is not available in the web interface; keys never leave it"
        ));
    }
    let Some(status) = wallet else {
        return Ok(());
    };
    if status == "unencrypted" && !reads(method) {
        return Err(format!(
            "{method} needs an encrypted wallet; encrypt it on the Security page first"
        ));
    }
    if method == "walletpassphrase" {
        let staking_only = params.get(2).and_then(Value::as_bool).unwrap_or(false);
        if !staking_only {
            let timeout = params.get(1).and_then(Value::as_i64).unwrap_or(0);
            if !(1..=MAX_FULL_UNLOCK_SECS).contains(&timeout) {
                return Err(format!(
                    "the web interface unlocks for spending for 1 to {MAX_FULL_UNLOCK_SECS} \
                     seconds only; unlock for staking to keep it open"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_never_leave() {
        for status in [None, Some("unlocked"), Some("unencrypted")] {
            assert!(check("dumpprivkey", &[json!("D...")], status).is_err());
            assert!(check("dumpwallet", &[], status).is_err());
        }
    }

    #[test]
    fn an_unencrypted_wallet_only_reads_and_encrypts() {
        let w = Some("unencrypted");
        assert!(check("getwalletinfo", &[], w).is_ok());
        assert!(check("listunspent", &[], w).is_ok());
        assert!(check("encryptwallet", &[json!("pass")], w).is_ok());
        assert!(check("sendtoaddress", &[json!("D"), json!(1)], w).is_err());
        assert!(check("getnewaddress", &[], w).is_ok());
        assert!(check("setstaking", &[json!(true)], w).is_err());
    }

    #[test]
    fn full_unlock_is_short() {
        let w = Some("locked");
        assert!(check("walletpassphrase", &[json!("p"), json!(0), json!(true)], w).is_ok());
        assert!(check("walletpassphrase", &[json!("p"), json!(60)], w).is_ok());
        assert!(check("walletpassphrase", &[json!("p"), json!(0)], w).is_err());
        assert!(check(
            "walletpassphrase",
            &[json!("p"), json!(601), json!(false)],
            w
        )
        .is_err());
        assert!(check("sendtoaddress", &[json!("D"), json!(1)], w).is_ok());
    }

    #[test]
    fn no_wallet_passes_all_but_key_exports() {
        assert!(check("setstaking", &[json!(true)], None).is_ok());
        assert!(check("dumphdinfo", &[], None).is_err());
    }
}
