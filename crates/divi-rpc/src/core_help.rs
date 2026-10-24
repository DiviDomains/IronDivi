// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Divi Core 3.0.0's `help`: its list of calls, and the whole help text of
//! the calls whose text is given here. The same text answers a call made
//! with the wrong number of arguments (-1, as Core's `fHelp` throw).

use crate::error::{codes, RpcError};
use crate::protocol::Params;

/// Divi Core's call table (rpcserver.cpp:323-466) as `help` lists it, in
/// Core's order (category, then name): category, name, the first line of
/// the call's help text, and whether the call needs a wallet
/// (requiresWalletLock). Core lists a call by the first line of its help,
/// so a few rows name another call (listbanned, bip38paperwallet) or none
/// (getcoinavailability); "hidden" calls are not listed.
const LIST: &[(&str, &str, &str, bool)] = &[
    ("addressindex", "getaddressbalance", "getaddressbalance <address>|<addresses> (only_vaults)", false),
    ("addressindex", "getaddressdeltas", "getaddressdeltas <address>|<addresses> (only_vaults)", false),
    ("addressindex", "getaddresstxids", "getaddresstxids <address>|<addresses> (only_vaults)", false),
    ("addressindex", "getaddressutxos", "getaddressutxos <address>|<addresses> (only_vaults)", false),
    ("blockchain", "getbestblockhash", "getbestblockhash", false),
    ("blockchain", "getblock", "getblock \"hash\" ( verbose )", false),
    ("blockchain", "getblockchaininfo", "getblockchaininfo", false),
    ("blockchain", "getblockcount", "getblockcount", false),
    ("blockchain", "getblockhash", "getblockhash index", false),
    ("blockchain", "getblockheader", "getblockheader \"hash\" ( verbose )", false),
    ("blockchain", "getchaintips", "getchaintips", false),
    ("blockchain", "getdifficulty", "getdifficulty", false),
    ("blockchain", "getlotteryblockwinners", "getlotteryblockwinners [block_height]", false),
    ("blockchain", "getmempoolinfo", "getmempoolinfo", false),
    ("blockchain", "getrawmempool", "getrawmempool ( verbose )", false),
    ("blockchain", "getspentinfo", "getspentinfo {txid:,index:}", false),
    ("blockchain", "gettxout", "gettxout \"txid\" n ( includemempool )", false),
    ("blockchain", "gettxoutsetinfo", "gettxoutsetinfo", false),
    ("blockchain", "reverseblocktransactions", "reverseblocktransactions \"hash\"", false),
    ("blockchain", "verifychain", "verifychain ( numblocks )", false),
    ("control", "getinfo", "getinfo", false),
    ("control", "help", "help ( \"command\" )", false),
    ("control", "stop", "stop", false),
    ("divi", "allocatefunds", "allocatefunds purpose alias tier ( \"pay wallet\" ( \"voting wallet\" ) )", false),
    ("divi", "ban", "ban [outdated|<ip_address>]", false),
    ("divi", "broadcaststartmasternode", "broadcaststartmasternode hex sig", false),
    ("divi", "clearbanned", "clearbanned", false),
    ("divi", "getmasternodecount", "getmasternodecount", false),
    ("divi", "getmasternodestatus", "getmasternodestatus", false),
    ("divi", "getmasternodewinners", "getmasternodewinners ( blocks \"filter\" )", false),
    ("divi", "importmnbroadcast", "importmnbroadcast \"broadcast_hex\"", false),
    ("divi", "listbanned", "clearbanned", false),
    ("divi", "listmasternodes", "listmasternodes ( \"filter\" )", false),
    ("divi", "listmnbroadcasts", "listmnbroadcasts", false),
    ("divi", "mnsync", "mnsync \"status|reset\"", false),
    ("divi", "setupmasternode", "setupmasternode alias txhash outputIndex collateralPubKey ip_address", true),
    ("divi", "signmnbroadcast", "signmnbroadcast mnhex", true),
    ("divi", "spork", "spork <name> [<value>]", false),
    ("divi", "startmasternode", "startmasternode alias", false),
    ("divi", "verifymasternodesetup", "verifymasternodesetup ip_address sigtime collateralPubKey masternodePubKey", true),
    ("generating", "generateblock", "generateblock ( options )", false),
    ("generating", "setgenerate", "setgenerate numberofblocks", false),
    ("getinvalid", "getinvalid", "getinvalid ", false),
    ("hidden", "invalidateblock", "", false),
    ("hidden", "reconsiderblock", "", false),
    ("hidden", "setmocktime", "", false),
    ("mining", "getmininginfo", "getmininginfo", false),
    ("mining", "prioritisetransaction", "prioritisetransaction <txid> <priority delta> <fee delta>", false),
    ("network", "addnode", "addnode \"node\" \"add|remove|onetry\"", false),
    ("network", "getaddednodeinfo", "getaddednodeinfo dns ( \"node\" )", false),
    ("network", "getconnectioncount", "getconnectioncount", false),
    ("network", "getnettotals", "getnettotals", false),
    ("network", "getnetworkinfo", "getnetworkinfo", false),
    ("network", "getpeerinfo", "getpeerinfo", false),
    ("network", "ping", "ping", false),
    ("rawtransactions", "createrawtransaction", "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,...}", false),
    ("rawtransactions", "decoderawtransaction", "decoderawtransaction \"hexstring\"", false),
    ("rawtransactions", "decodescript", "decodescript \"hex\"", false),
    ("rawtransactions", "getrawtransaction", "getrawtransaction \"txid\" ( verbose )", false),
    ("rawtransactions", "sendrawtransaction", "sendrawtransaction \"hexstring\" ( allowhighfees )", false),
    ("rawtransactions", "signrawtransaction", "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )", false),
    ("rawtransactions", "signtransactionwithaddresskey", "signTransactionWithAddressKey", false),
    ("util", "createmultisig", "createmultisig nrequired [\"key\",...]", false),
    ("util", "validateaddress", "validateaddress \"diviaddress\"", false),
    ("util", "verifymessage", "verifymessage \"diviaddress\" \"signature\" \"message\"", false),
    ("wallet", "addmultisigaddress", "addmultisigaddress nrequired [\"key\",...] ( \"account\" )", true),
    ("wallet", "addvault", "addvault \"<owner_address>:<manager_address>\" funding_txhash", true),
    ("wallet", "backupwallet", "backupwallet \"destination\"", true),
    ("wallet", "bip38decrypt", "bip38decrypt \"diviaddress\"", true),
    ("wallet", "bip38paperwallet", "bip38encrypt \"password\"", true),
    ("wallet", "debitvaultbyname", "debitvaultbyname source destination amount (feeMode)", true),
    ("wallet", "dumphdinfo", "dumphdinfo", true),
    ("wallet", "dumpprivkey", "dumpprivkey \"diviaddress\"", true),
    ("wallet", "encryptwallet", "encryptwallet \"passphrase\"", true),
    ("wallet", "fundvault", "fundvault \"[owner_address:]manager_address\" amount", true),
    ("wallet", "getaccount", "getaccount \"diviaddress\"", true),
    ("wallet", "getaccountaddress", "getaccountaddress \"account\"", true),
    ("wallet", "getaddressesbyaccount", "getaddressesbyaccount \"account\"", true),
    ("wallet", "getbalance", "getbalance ( \"account\" minconf includeWatchonly )", true),
    ("wallet", "getcoinavailability", "", true),
    ("wallet", "getnewaddress", "getnewaddress ( \"account\" )", true),
    ("wallet", "getrawchangeaddress", "getrawchangeaddress", true),
    ("wallet", "getreceivedbyaccount", "getreceivedbyaccount \"account\" ( minconf )", true),
    ("wallet", "getreceivedbyaddress", "getreceivedbyaddress \"diviaddress\" ( minconf )", true),
    ("wallet", "getstakingstatus", "getstakingstatus", true),
    ("wallet", "gettransaction", "gettransaction \"txid\" ( includeWatchonly )", true),
    ("wallet", "getunconfirmedbalance", "getunconfirmedbalance", true),
    ("wallet", "getwalletinfo", "getwalletinfo", true),
    ("wallet", "importaddress", "importaddress \"address\" ( \"label\" rescan )", true),
    ("wallet", "importprivkey", "importprivkey \"diviprivkey\" ( \"label\" rescan )", true),
    ("wallet", "keypoolrefill", "keypoolrefill ( newsize )", true),
    ("wallet", "listaccounts", "listaccounts ( minconf includeWatchonly)", true),
    ("wallet", "listlockunspent", "listlockunspent", true),
    ("wallet", "listreceivedbyaccount", "listreceivedbyaccount ( minconf includeempty includeWatchonly)", true),
    ("wallet", "listreceivedbyaddress", "listreceivedbyaddress ( minconf includeempty includeWatchonly)", true),
    ("wallet", "listsinceblock", "listsinceblock ( \"blockhash\" target-confirmations includeWatchonly)", true),
    ("wallet", "listtransactions", "listtransactions ( \"account\" count from includeWatchonly)", true),
    ("wallet", "listunspent", "listunspent ( minconf maxconf  [\"address\",...] )", true),
    ("wallet", "loadwallet", "loadwallet \"walletFilename\"", true),
    ("wallet", "lockunspent", "lockunspent unlock [{\"txid\":\"txid\",\"vout\":n},...]", true),
    ("wallet", "reclaimvaultfunds", "reclaimvaultfunds destination amount (feeMode|metadata) ( \"comment\" \"comment-to\" )", true),
    ("wallet", "removevault", "removevault \"<owner_address>:<manager_address>\"", true),
    ("wallet", "sendfrom", "sendfrom \"fromaccount\" \"todiviaddress\" amount ( \"comment\" \"comment-to\" )", true),
    ("wallet", "sendmany", "sendmany \"fromaccount\" {\"address\":amount,...} ( \"comment\" )", true),
    ("wallet", "sendtoaddress", "sendtoaddress \"diviaddress\" amount (feeMode|metadata)( \"comment\" \"comment-to\" )", true),
    ("wallet", "setaccount", "setaccount \"diviaddress\" \"account\"", true),
    ("wallet", "signmessage", "signmessage \"diviaddress\" \"message\" \"input_format\" \"output_format\"", true),
    ("wallet", "walletlock", "walletlock", true),
    ("wallet", "walletpassphrase", "walletpassphrase \"passphrase\" timeout ( stakingOnly )", true),
    ("wallet", "walletpassphrasechange", "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"", true),
];

/// One state's help text of a call: the same as with an unencrypted wallet,
/// none (divid answers "help: unknown command: <call>"), or this text
#[derive(Clone, Copy, Debug)]
enum Help {
    Same,
    Unknown,
    Text(&'static str),
}

/// Divi Core 3.0.0's help text of each of its calls, as divid 3.0.0 answers
/// `help <call>`: with an unencrypted wallet, then with an encrypted one and
/// without a wallet. The texts are taken from divid; sample addresses and
/// hashes in their examples are written "diviaddress" and "hash".
const TEXTS: &[(&str, Help, Help, Help)] = &[
    (
        "addmultisigaddress",
        Help::Text(include_str!("core_help/addmultisigaddress.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "addnode",
        Help::Text(include_str!("core_help/addnode.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "addvault",
        Help::Text(include_str!("core_help/addvault.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "allocatefunds",
        Help::Text(include_str!("core_help/allocatefunds.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "backupwallet",
        Help::Text(include_str!("core_help/backupwallet.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "ban",
        Help::Text(include_str!("core_help/ban.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "bip38decrypt",
        Help::Text(include_str!("core_help/bip38decrypt.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "bip38paperwallet",
        Help::Text(include_str!("core_help/bip38paperwallet.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "broadcaststartmasternode",
        Help::Text(include_str!("core_help/broadcaststartmasternode.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "clearbanned",
        Help::Text(include_str!("core_help/clearbanned.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "createmultisig",
        Help::Text(include_str!("core_help/createmultisig.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "createrawtransaction",
        Help::Text(include_str!("core_help/createrawtransaction.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "debitvaultbyname",
        Help::Text(include_str!("core_help/debitvaultbyname.txt")),
        Help::Text(include_str!("core_help/debitvaultbyname.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "decoderawtransaction",
        Help::Text(include_str!("core_help/decoderawtransaction.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "decodescript",
        Help::Text(include_str!("core_help/decodescript.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "dumphdinfo",
        Help::Text(include_str!("core_help/dumphdinfo.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "dumpprivkey",
        Help::Text(include_str!("core_help/dumpprivkey.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "encryptwallet",
        Help::Text(include_str!("core_help/encryptwallet.txt")),
        Help::Unknown,
        Help::Unknown,
    ),
    (
        "fundvault",
        Help::Text(include_str!("core_help/fundvault.txt")),
        Help::Text(include_str!("core_help/fundvault.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "generateblock",
        Help::Text(include_str!("core_help/generateblock.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getaccount",
        Help::Text(include_str!("core_help/getaccount.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getaccountaddress",
        Help::Text(include_str!("core_help/getaccountaddress.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getaddednodeinfo",
        Help::Text(include_str!("core_help/getaddednodeinfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getaddressbalance",
        Help::Text(include_str!("core_help/getaddressbalance.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getaddressdeltas",
        Help::Text(include_str!("core_help/getaddressdeltas.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getaddressesbyaccount",
        Help::Text(include_str!("core_help/getaddressesbyaccount.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getaddresstxids",
        Help::Text(include_str!("core_help/getaddresstxids.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getaddressutxos",
        Help::Text(include_str!("core_help/getaddressutxos.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getbalance",
        Help::Text(include_str!("core_help/getbalance.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getbestblockhash",
        Help::Text(include_str!("core_help/getbestblockhash.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getblock",
        Help::Text(include_str!("core_help/getblock.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getblockchaininfo",
        Help::Text(include_str!("core_help/getblockchaininfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getblockcount",
        Help::Text(include_str!("core_help/getblockcount.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getblockhash",
        Help::Text(include_str!("core_help/getblockhash.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getblockheader",
        Help::Text(include_str!("core_help/getblockheader.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getchaintips",
        Help::Text(include_str!("core_help/getchaintips.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getcoinavailability",
        Help::Text(include_str!("core_help/getcoinavailability.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getconnectioncount",
        Help::Text(include_str!("core_help/getconnectioncount.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getdifficulty",
        Help::Text(include_str!("core_help/getdifficulty.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getinfo",
        Help::Text(include_str!("core_help/getinfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getinvalid",
        Help::Text(include_str!("core_help/getinvalid.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getlotteryblockwinners",
        Help::Text(include_str!("core_help/getlotteryblockwinners.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getmasternodecount",
        Help::Text(include_str!("core_help/getmasternodecount.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getmasternodestatus",
        Help::Text(include_str!("core_help/getmasternodestatus.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getmasternodewinners",
        Help::Text(include_str!("core_help/getmasternodewinners.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getmempoolinfo",
        Help::Text(include_str!("core_help/getmempoolinfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getmininginfo",
        Help::Text(include_str!("core_help/getmininginfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getnettotals",
        Help::Text(include_str!("core_help/getnettotals.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getnetworkinfo",
        Help::Text(include_str!("core_help/getnetworkinfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getnewaddress",
        Help::Text(include_str!("core_help/getnewaddress.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getpeerinfo",
        Help::Text(include_str!("core_help/getpeerinfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getrawchangeaddress",
        Help::Text(include_str!("core_help/getrawchangeaddress.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getrawmempool",
        Help::Text(include_str!("core_help/getrawmempool.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getrawtransaction",
        Help::Text(include_str!("core_help/getrawtransaction.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getreceivedbyaccount",
        Help::Text(include_str!("core_help/getreceivedbyaccount.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getreceivedbyaddress",
        Help::Text(include_str!("core_help/getreceivedbyaddress.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getspentinfo",
        Help::Text(include_str!("core_help/getspentinfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getstakingstatus",
        Help::Text(include_str!("core_help/getstakingstatus.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "gettransaction",
        Help::Text(include_str!("core_help/gettransaction.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "gettxout",
        Help::Text(include_str!("core_help/gettxout.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "gettxoutsetinfo",
        Help::Text(include_str!("core_help/gettxoutsetinfo.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "getunconfirmedbalance",
        Help::Text(include_str!("core_help/getunconfirmedbalance.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "getwalletinfo",
        Help::Text(include_str!("core_help/getwalletinfo.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "help",
        Help::Text(include_str!("core_help/help.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "importaddress",
        Help::Text(include_str!("core_help/importaddress.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "importmnbroadcast",
        Help::Text(include_str!("core_help/importmnbroadcast.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "importprivkey",
        Help::Text(include_str!("core_help/importprivkey.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "invalidateblock",
        Help::Text(include_str!("core_help/invalidateblock.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "keypoolrefill",
        Help::Text(include_str!("core_help/keypoolrefill.txt")),
        Help::Text(include_str!("core_help/keypoolrefill.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "listaccounts",
        Help::Text(include_str!("core_help/listaccounts.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "listbanned",
        Help::Text(include_str!("core_help/listbanned.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "listlockunspent",
        Help::Text(include_str!("core_help/listlockunspent.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "listmasternodes",
        Help::Text(include_str!("core_help/listmasternodes.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "listmnbroadcasts",
        Help::Text(include_str!("core_help/listmnbroadcasts.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "listreceivedbyaccount",
        Help::Text(include_str!("core_help/listreceivedbyaccount.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "listreceivedbyaddress",
        Help::Text(include_str!("core_help/listreceivedbyaddress.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "listsinceblock",
        Help::Text(include_str!("core_help/listsinceblock.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "listtransactions",
        Help::Text(include_str!("core_help/listtransactions.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "listunspent",
        Help::Text(include_str!("core_help/listunspent.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "loadwallet",
        Help::Text(include_str!("core_help/loadwallet.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "lockunspent",
        Help::Text(include_str!("core_help/lockunspent.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "mnsync",
        Help::Text(include_str!("core_help/mnsync.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "ping",
        Help::Text(include_str!("core_help/ping.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "prioritisetransaction",
        Help::Text(include_str!("core_help/prioritisetransaction.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "reclaimvaultfunds",
        Help::Text(include_str!("core_help/reclaimvaultfunds.txt")),
        Help::Text(include_str!("core_help/reclaimvaultfunds.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "reconsiderblock",
        Help::Text(include_str!("core_help/reconsiderblock.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "removevault",
        Help::Text(include_str!("core_help/removevault.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "reverseblocktransactions",
        Help::Text(include_str!("core_help/reverseblocktransactions.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "sendfrom",
        Help::Text(include_str!("core_help/sendfrom.txt")),
        Help::Text(include_str!("core_help/sendfrom.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "sendmany",
        Help::Text(include_str!("core_help/sendmany.txt")),
        Help::Text(include_str!("core_help/sendmany.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "sendrawtransaction",
        Help::Text(include_str!("core_help/sendrawtransaction.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "sendtoaddress",
        Help::Text(include_str!("core_help/sendtoaddress.txt")),
        Help::Text(include_str!("core_help/sendtoaddress.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "setaccount",
        Help::Text(include_str!("core_help/setaccount.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "setgenerate",
        Help::Text(include_str!("core_help/setgenerate.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "setmocktime",
        Help::Text(include_str!("core_help/setmocktime.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "setupmasternode",
        Help::Text(include_str!("core_help/setupmasternode.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "signmessage",
        Help::Text(include_str!("core_help/signmessage.txt")),
        Help::Text(include_str!("core_help/signmessage.encrypted.txt")),
        Help::Unknown,
    ),
    (
        "signmnbroadcast",
        Help::Text(include_str!("core_help/signmnbroadcast.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "signrawtransaction",
        Help::Text(include_str!("core_help/signrawtransaction.txt")),
        Help::Text(include_str!("core_help/signrawtransaction.encrypted.txt")),
        Help::Same,
    ),
    (
        "signtransactionwithaddresskey",
        Help::Text(include_str!("core_help/signtransactionwithaddresskey.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "spork",
        Help::Text(include_str!("core_help/spork.txt")),
        Help::Text(include_str!("core_help/spork.encrypted.txt")),
        Help::Same,
    ),
    (
        "startmasternode",
        Help::Text(include_str!("core_help/startmasternode.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "stop",
        Help::Text(include_str!("core_help/stop.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "validateaddress",
        Help::Text(include_str!("core_help/validateaddress.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "verifychain",
        Help::Text(include_str!("core_help/verifychain.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "verifymasternodesetup",
        Help::Text(include_str!("core_help/verifymasternodesetup.txt")),
        Help::Same,
        Help::Unknown,
    ),
    (
        "verifymessage",
        Help::Text(include_str!("core_help/verifymessage.txt")),
        Help::Same,
        Help::Same,
    ),
    (
        "walletlock",
        Help::Unknown,
        Help::Text(include_str!("core_help/walletlock.encrypted.txt")),
        Help::Same,
    ),
    (
        "walletpassphrase",
        Help::Unknown,
        Help::Text(include_str!("core_help/walletpassphrase.encrypted.txt")),
        Help::Same,
    ),
    (
        "walletpassphrasechange",
        Help::Unknown,
        Help::Text(include_str!(
            "core_help/walletpassphrasechange.encrypted.txt"
        )),
        Help::Same,
    ),
];

/// Whether `method` is one of Divi Core's calls (rpcserver.cpp:324-467)
pub fn is_core_call(method: &str) -> bool {
    TEXTS.iter().any(|(name, ..)| *name == method)
}

/// The whole help text of a Divi Core call as divid 3.0.0 gives it with an
/// unencrypted wallet
pub fn text(method: &str) -> Option<&'static str> {
    text_for(method, Some(false))
}

/// The whole help text of a Divi Core call in a wallet state: `encrypted` is
/// None without a wallet. None: divid answers "help: unknown command" (a
/// wallet call without a wallet, walletlock on an unencrypted wallet), or no
/// Divi Core call has that name.
pub fn text_for(method: &str, encrypted: Option<bool>) -> Option<&'static str> {
    let (_, plain, crypted, none) = TEXTS.iter().find(|(name, ..)| *name == method)?;
    let state = match encrypted {
        Some(false) => plain,
        Some(true) => crypted,
        None => none,
    };
    match (state, plain) {
        (Help::Text(t), _) | (Help::Same, Help::Text(t)) => Some(t),
        _ => None,
    }
}

/// Whether Divi Core answers `method` with these arguments by its help text
/// (-1): each call's `if (fHelp || params.size() ...)` check
/// (rpcblockchain.cpp, rpcmining.cpp, rpcmisc.cpp, rpcnet.cpp,
/// rpcrawtransaction.cpp, rpcwallet.cpp, rpcdump.cpp, rpcmasternode.cpp,
/// rpclottery.cpp). `encrypted` is None without a wallet. Named parameters
/// are left to the call.
pub fn usage_refused(method: &str, params: &Params, encrypted: Option<bool>) -> bool {
    if matches!(params, Params::Object(_)) {
        return false;
    }
    let n = params.len();
    let word = |i: usize| params.get(i).and_then(|v| v.as_str());
    let is_object = |i: usize| params.get(i).is_some_and(|v| v.is_object());
    let (min, max) = match method {
        // rpcnet.cpp:157-161: the command is read first (get_str), then checked
        "addnode" => {
            return n != 2 || word(1).is_some_and(|c| !matches!(c, "add" | "remove" | "onetry"))
        }
        // rpcmisc.cpp:166
        "mnsync" => return n != 1 || word(0).is_some_and(|m| !matches!(m, "status" | "reset")),
        // rpcmisc.cpp:277-312: anything but show, active or a name and a value
        "spork" => return !(n == 2 || (n == 1 && matches!(word(0), Some("show" | "active")))),
        // rpcmisc.cpp:881
        "getspentinfo" => return n != 1 || !is_object(0),
        // rpcwallet.cpp:1039
        "fundvault" => return !(1..=2).contains(&n) || (n == 1 && !is_object(0)),
        // rpcwallet.cpp:2669, :2575, :2630: counted only on an encrypted wallet
        "walletlock" if encrypted == Some(true) => (0, 0),
        "walletpassphrase" if encrypted == Some(true) => (2, 3),
        "walletpassphrasechange" if encrypted == Some(true) => (2, 2),
        "walletlock" | "walletpassphrase" | "walletpassphrasechange" => return false,
        // rpcwallet.cpp:2694: counted only on an unencrypted wallet
        "encryptwallet" if encrypted == Some(true) => return false,
        // rpcwallet.cpp:1194 takes exactly one; irondivid still takes the second
        // argument older IronDivi callers send (see scripts/vault-replies)
        "removevault" => (1, 2),
        // rpcwallet.cpp:2366, rpcrawtransaction.cpp:568: no count
        "listsinceblock" | "signtransactionwithaddresskey" => return false,
        _ => match argument_count(method) {
            Some(range) => range,
            None => return false,
        },
    };
    !(min..=max).contains(&n)
}

/// The fewest and most arguments of the Divi Core calls whose check is a count
fn argument_count(method: &str) -> Option<(usize, usize)> {
    Some(match method {
        "getinfo"
        | "getnetworkinfo"
        | "getconnectioncount"
        | "getnettotals"
        | "getpeerinfo"
        | "ping"
        | "getblockchaininfo"
        | "getbestblockhash"
        | "getblockcount"
        | "getchaintips"
        | "getdifficulty"
        | "getmempoolinfo"
        | "gettxoutsetinfo"
        | "getmininginfo"
        | "getmasternodecount"
        | "getmasternodestatus"
        | "listmnbroadcasts"
        | "dumphdinfo"
        | "getstakingstatus"
        | "getunconfirmedbalance"
        | "getwalletinfo"
        | "listlockunspent" => (0, 0),
        "help"
        | "stop"
        | "getlotteryblockwinners"
        | "getrawmempool"
        | "getinvalid"
        | "generateblock"
        | "listmasternodes"
        | "clearbanned"
        | "listbanned"
        | "getnewaddress"
        | "getrawchangeaddress"
        | "keypoolrefill"
        | "getcoinavailability" => (0, 1),
        "verifychain" | "listaccounts" => (0, 2),
        "getmasternodewinners"
        | "getbalance"
        | "listreceivedbyaccount"
        | "listreceivedbyaddress"
        | "listunspent" => (0, 3),
        "listtransactions" => (0, 4),
        "getblockhash"
        | "reverseblocktransactions"
        | "invalidateblock"
        | "reconsiderblock"
        | "setgenerate"
        | "decoderawtransaction"
        | "decodescript"
        | "validateaddress"
        | "setmocktime"
        | "signmnbroadcast"
        | "importmnbroadcast"
        | "ban"
        | "backupwallet"
        | "dumpprivkey"
        | "bip38paperwallet"
        | "encryptwallet"
        | "getaccountaddress"
        | "getaccount"
        | "getaddressesbyaccount"
        | "loadwallet" => (1, 1),
        "getaddednodeinfo"
        | "getblock"
        | "getblockheader"
        | "getrawtransaction"
        | "sendrawtransaction"
        | "broadcaststartmasternode"
        | "startmasternode"
        | "getreceivedbyaccount"
        | "getreceivedbyaddress"
        | "gettransaction"
        | "lockunspent"
        | "setaccount"
        | "getaddressbalance"
        | "getaddressdeltas"
        | "getaddresstxids"
        | "getaddressutxos" => (1, 2),
        "importprivkey" | "importaddress" => (1, 3),
        "signrawtransaction" => (1, 4),
        "createrawtransaction" | "createmultisig" | "bip38decrypt" | "addvault" => (2, 2),
        "addmultisigaddress" => (2, 3),
        "sendmany" | "signmessage" => (2, 4),
        "sendtoaddress" | "reclaimvaultfunds" => (2, 5),
        "gettxout" => (2, 3),
        "prioritisetransaction" | "verifymessage" | "allocatefunds" => (3, 3),
        "sendfrom" => (3, 5),
        "debitvaultbyname" => (3, 4),
        "verifymasternodesetup" => (4, 4),
        "setupmasternode" => (5, 6),
        _ => return None,
    })
}

/// Divi Core's answer to a call made with the wrong number of arguments, or to
/// a string argument given as another type (json_spirit's get_str): -1 with
/// the call's help text, or "value is type X, expected str"
pub(crate) fn check_arguments(
    method: &str,
    params: &Params,
    (min, max): (usize, usize),
    strings: usize,
) -> Result<(), RpcError> {
    if !(min..=max).contains(&params.len()) {
        return Err(RpcError::new(
            codes::MISC_ERROR,
            text(method).unwrap_or(method),
        ));
    }
    for value in (0..strings).filter_map(|i| params.get(i)) {
        if !value.is_string() {
            let got = crate::wallet::json_spirit_type(value);
            return Err(RpcError::new(
                codes::MISC_ERROR,
                format!("value is type {got}, expected str"),
            ));
        }
    }
    Ok(())
}

/// The command list `help` answers with no argument (rpcserver.cpp:235-289):
/// each Divi Core call irondivid has, under Core's category, as Core lists
/// it; then irondivid's own calls under their categories, each marked
/// "(irondivid)". `calls` is irondivid's list of (category, name);
/// `encrypted` is None without a wallet, as Core then leaves out the calls
/// that need one. walletlock, walletpassphrase and walletpassphrasechange are
/// listed only for an encrypted wallet and encryptwallet only for a plain one,
/// as their help is thrown only then (rpcwallet.cpp).
pub fn list(calls: &[(&str, &str)], encrypted: Option<bool>) -> String {
    let has = |name: &str| calls.iter().any(|(_, n)| *n == name);
    let shown = |name: &str, wallet: bool| match (name, encrypted) {
        (_, None) if wallet => false,
        ("walletlock" | "walletpassphrase" | "walletpassphrasechange", e) => e == Some(true),
        ("encryptwallet", e) => e == Some(false),
        _ => true,
    };
    let mut out = String::new();
    let mut category = "";
    let section = |out: &mut String, name: &str| {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("== {name} ==\n"));
    };
    for (cat, name, line, wallet) in LIST {
        if *cat == "hidden" || !has(name) || !shown(name, *wallet) {
            continue;
        }
        if *cat != category {
            category = cat;
            let mut title = cat.to_string();
            title[..1].make_ascii_uppercase();
            section(&mut out, &title);
        }
        out.push_str(line);
        out.push('\n');
    }
    let mut category = "";
    for (cat, name) in calls {
        if LIST.iter().any(|(_, n, _, _)| n == name) {
            continue;
        }
        if *cat != category {
            category = cat;
            section(&mut out, &format!("{cat} (irondivid)"));
        }
        out.push_str(name);
        out.push('\n');
    }
    out.pop();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_in_cores_order() {
        let mut keys: Vec<String> = LIST.iter().map(|(c, n, _, _)| format!("{c}{n}")).collect();
        let sorted = {
            let mut s = keys.clone();
            s.sort();
            s
        };
        assert_eq!(keys, sorted);
        keys.dedup();
        assert_eq!(keys.len(), LIST.len());
    }

    #[test]
    fn every_text_starts_with_its_list_line() {
        for (category, name, line, _) in LIST {
            // hidden calls are not listed, so they have no line
            if *category == "hidden" {
                continue;
            }
            if let Some(text) = text(name) {
                // split, not lines: getcoinavailability's text is empty
                assert_eq!(text.split('\n').next(), Some(*line), "{name}");
            }
        }
    }

    #[test]
    fn list_follows_the_wallet() {
        let calls = [
            ("Wallet", "encryptwallet"),
            ("Wallet", "walletlock"),
            ("Control", "help"),
            ("Logging", "getlogconfig"),
        ];
        assert_eq!(
            list(&calls, Some(false)),
            "== Control ==\nhelp ( \"command\" )\n\n== Wallet ==\nencryptwallet \"passphrase\"\n\n== Logging (irondivid) ==\ngetlogconfig"
        );
        assert_eq!(
            list(&calls, Some(true)),
            "== Control ==\nhelp ( \"command\" )\n\n== Wallet ==\nwalletlock\n\n== Logging (irondivid) ==\ngetlogconfig"
        );
        assert_eq!(
            list(&calls, None),
            "== Control ==\nhelp ( \"command\" )\n\n== Logging (irondivid) ==\ngetlogconfig"
        );
    }
}
