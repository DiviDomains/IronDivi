// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! What the web interface lets a signed-in user call. It never hands out
//! keys, it never unlocks the wallet for spending past a short while, and
//! until the wallet is encrypted it only reads and offers to encrypt.
//!
//! A web session is not the node operator. It may read the node and use the
//! wallet; anything else (stopping the node, writing a file at a path,
//! mining, forcing chain state, key exports) is refused here and stays with
//! direct RPC (`irondivi-cli`), which this gate does not touch. A call that
//! is in neither list below is refused, so a new RPC method is operator-only
//! until it is added on purpose.

use serde_json::Value;

/// Calls that write keys out, or return a key made from the wallet's
/// (`bip38encrypt` seals a wallet key under a caller-chosen passphrase;
/// `setupmasternode` prints the masternode key as WIF); the web interface
/// never makes them
const KEY_EXPORTS: &[&str] = &[
    "dumpprivkey",
    "dumpwallet",
    "dumphdinfo",
    "bip38encrypt",
    "bip38paperwallet",
    "setupmasternode",
];

/// Calls that only read, or compute from what they are given
const READS: &[&str] = &[
    "help",
    "ping",
    "uptime",
    "getblockcount",
    "getbestblockhash",
    "getblockhash",
    "getblock",
    "getblockheader",
    "getblockchaininfo",
    "getinfo",
    "getchaintips",
    "getdifficulty",
    "gettxoutsetinfo",
    "getrawmempool",
    "getmempoolinfo",
    "gettxout",
    "getrawtransaction",
    "decoderawtransaction",
    "decodescript",
    "verifychain",
    "getmininginfo",
    "getinvalid",
    "getaddressdeltas",
    "getaddresstxids",
    "getspentinfo",
    "getaddressbalance",
    "getaddressutxos",
    "getaddresshistory",
    "gettxindex",
    "getnetworkinfo",
    "getpeerinfo",
    "getpeerscores",
    "getconnectioncount",
    "getnettotals",
    "getaddednodeinfo",
    "listbanned",
    "getnewaddress",
    "getrawchangeaddress",
    "getaccountaddress",
    "validateaddress",
    "validateaddresses",
    "getaddressinfo",
    "getbalance",
    "getunconfirmedbalance",
    "getimmaturebalance",
    "getwalletinfo",
    "listunspent",
    "listlockunspent",
    "gettransaction",
    "listtransactions",
    "listsinceblock",
    "getaddressesbylabel",
    "getaddressesbyaccount",
    "getaccount",
    "listaccounts",
    "getreceivedbyaccount",
    "listreceivedbyaccount",
    "getreceivedbyaddress",
    "listreceivedbyaddress",
    "getkeypoolsize",
    "verifymessage",
    "createmultisig",
    "estimatefee",
    "estimatesmartfee",
    "estimatepriority",
    "getlotteryblockwinners",
    "getpqposture",
    "getstakingstatus",
    "getmintinginfo",
    "getstakesplitthreshold",
    "getlitewalletinfo",
    "getcoinavailability",
    "getmasternodecount",
    "getmasternodestatus",
    "getmasternodewinners",
    "listmasternodes",
    "listmnbroadcasts",
    "verifymasternodesetup",
    "getdiaginfo",
    "getlogconfig",
];

/// Calls a wallet user makes: spending, receiving, locking, vaults, staking,
/// and the owner's side of a masternode. Each needs an encrypted wallet.
/// `addnode` is the one peer call kept, as the Settings page already sets it
const WALLET_ACTIONS: &[&str] = &[
    "encryptwallet",
    "walletpassphrase",
    "walletlock",
    "walletpassphrasechange",
    "sendtoaddress",
    "sendmany",
    "sendfrom",
    "keypoolrefill",
    "importaddress",
    "importprivkey",
    "bip38decrypt",
    "addmultisigaddress",
    "setaccount",
    "signmessage",
    "createrawtransaction",
    "signrawtransaction",
    "signrawtransactionwithwallet",
    "signtransactionwithaddresskey",
    "sendrawtransaction",
    "lockunspent",
    "rescanblockchain",
    "setstaking",
    "setstakesplitthreshold",
    "addvault",
    "removevault",
    "fundvault",
    "debitvaultbyname",
    "reclaimvaultfunds",
    "allocatefunds",
    "planpqsweep",
    "startmasternode",
    "broadcaststartmasternode",
    "signmnbroadcast",
    "importmnbroadcast",
    "addnode",
];

/// The longest full unlock the web interface grants, in seconds
pub const MAX_FULL_UNLOCK_SECS: i64 = 600;

/// Calls an unencrypted wallet may still make: reads, and encrypting it
fn reads(method: &str) -> bool {
    READS.contains(&method) || matches!(method, "encryptwallet" | "planpqsweep")
}

/// Whether the call may go to the daemon, given the wallet's
/// `encryption_status` (None without a wallet)
pub fn check(method: &str, params: &[Value], wallet: Option<&str>) -> Result<(), String> {
    if KEY_EXPORTS.contains(&method) {
        return Err(format!(
            "{method} is not available in the web interface; keys never leave it"
        ));
    }
    if !READS.contains(&method) && !WALLET_ACTIONS.contains(&method) {
        return Err(format!(
            "{method} is for the node operator, not a web session; use irondivi-cli"
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

    /// Every state a wallet can be in, and none
    const STATES: [Option<&str>; 5] = [
        None,
        Some("unencrypted"),
        Some("locked"),
        Some("unlocked"),
        Some("unlocked_for_staking"),
    ];

    #[test]
    fn keys_never_leave() {
        for status in STATES {
            assert!(check("dumpprivkey", &[json!("D...")], status).is_err());
            assert!(check("dumpwallet", &[], status).is_err());
        }
    }

    #[test]
    fn key_export_equivalents_are_refused_in_every_wallet_state() {
        for method in [
            "dumpprivkey",
            "dumpwallet",
            "dumphdinfo",
            "bip38encrypt",
            "bip38paperwallet",
            "setupmasternode",
        ] {
            for status in STATES {
                let err = check(method, &[json!("x"), json!("y")], status).unwrap_err();
                assert!(err.contains("keys never leave"), "{method}: {err}");
            }
        }
    }

    #[test]
    fn operator_calls_are_refused_in_every_wallet_state() {
        for method in [
            "backupwallet",
            "stop",
            "loadwallet",
            "setgenerate",
            "generateblock",
            "setmocktime",
            "invalidateblock",
            "reconsiderblock",
            "reverseblocktransactions",
            "prioritisetransaction",
            "spork",
            "mnsync",
            "setlogconfig",
            "setban",
            "ban",
            "clearbanned",
            "disconnectnode",
            // Not an RPC method at all: unknown names are refused too
            "futurekeyexport",
            "DUMPPRIVKEY",
            "dumpprivkey ",
            "",
        ] {
            for status in STATES {
                let err = check(method, &[json!("/tmp/x")], status).unwrap_err();
                assert!(
                    err.contains("operator") || err.contains("keys never"),
                    "{method}: {err}"
                );
            }
        }
    }

    #[test]
    fn wallet_workflows_still_work_once_encrypted() {
        for method in [
            "sendtoaddress",
            "sendmany",
            "sendfrom",
            "importprivkey",
            "createrawtransaction",
            "signrawtransaction",
            "sendrawtransaction",
            "signmessage",
            "lockunspent",
            "setstaking",
            "setstakesplitthreshold",
            "fundvault",
            "walletlock",
            "walletpassphrasechange",
            "addnode",
        ] {
            for status in [None, Some("locked"), Some("unlocked")] {
                assert!(
                    check(method, &[json!("D"), json!(1)], status).is_ok(),
                    "{method}"
                );
            }
            assert!(
                check(method, &[json!("D"), json!(1)], Some("unencrypted")).is_err(),
                "{method}"
            );
        }
    }

    #[test]
    fn monitoring_and_reads_work_in_every_wallet_state() {
        for method in [
            "help",
            "ping",
            "getblockcount",
            "getblockchaininfo",
            "getpeerinfo",
            "getwalletinfo",
            "getbalance",
            "listunspent",
            "listtransactions",
            "gettransaction",
            "getstakingstatus",
            "getpqposture",
            "getdiaginfo",
            "getlogconfig",
            "validateaddress",
            "verifymessage",
        ] {
            for status in STATES {
                assert!(check(method, &[], status).is_ok(), "{method}");
            }
        }
    }

    #[test]
    fn the_lists_do_not_overlap() {
        for method in READS.iter().chain(WALLET_ACTIONS) {
            assert!(!KEY_EXPORTS.contains(method), "{method}");
        }
        for method in READS {
            assert!(!WALLET_ACTIONS.contains(method), "{method}");
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
    fn no_wallet_passes_wallet_calls_but_not_key_exports_or_operator_calls() {
        assert!(check("setstaking", &[json!(true)], None).is_ok());
        assert!(check("dumphdinfo", &[], None).is_err());
        assert!(check("backupwallet", &[json!("/tmp/w.dat")], None).is_err());
        assert!(check("stop", &[], None).is_err());
    }
}
