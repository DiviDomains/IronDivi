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

/// The whole help text of a call as Divi Core writes it, for the calls given
/// here. Core's examples name sample addresses; these say "diviaddress".
pub fn text(method: &str) -> Option<&'static str> {
    Some(match method {
        "getaccount" => "getaccount \"diviaddress\"\n\nReturns the account associated with the given address.\n\nArguments:\n1. \"diviaddress\"  (string, required) The divi address for account lookup.\n\nResult:\n\"accountname\"        (string) the account address\n\nExamples:\n> divi-cli getaccount \"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getaccount\", \"params\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "getaccountaddress" => "getaccountaddress \"account\"\n\nReturns the current DIVI address for receiving payments to this account.\n\nArguments:\n1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n\nResult:\n\"diviaddress\"   (string) The account divi address\n\nExamples:\n> divi-cli getaccountaddress \n> divi-cli getaccountaddress \"\"\n> divi-cli getaccountaddress \"myaccount\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getaccountaddress\", \"params\": [\"myaccount\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "getaddressesbyaccount" => "getaddressesbyaccount \"account\"\n\nReturns the list of addresses for the given account.\n\nArguments:\n1. \"account\"  (string, required) The account name.\n\nResult:\n[                     (json array of string)\n  \"diviaddress\"  (string) a divi address associated with the given account\n  ,...\n]\n\nExamples:\n> divi-cli getaddressesbyaccount \"tabby\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getaddressesbyaccount\", \"params\": [\"tabby\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "getdifficulty" => "getdifficulty\n\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n\nResult:\nn.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n\nExamples:\n> divi-cli getdifficulty \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getdifficulty\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "getinfo" => "getinfo\nReturns an object containing various state info.\n\nResult:\n{\n  \"version\": xxxxx,           (numeric) the server version\n  \"protocolversion\": xxxxx,   (numeric) the protocol version\n  \"walletversion\": xxxxx,     (numeric) the wallet version\n  \"balance\": xxxxxxx,         (numeric) the total divi balance of the wallet\n  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n  \"timeoffset\": xxxxx,        (numeric) the time offset\n  \"connections\": xxxxx,       (numeric) the number of connections\n  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n  \"moneysupply\" : \"supply\"       (numeric) The money supply when this block was added to the blockchain\n  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool\n  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in divi/kb\n  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in divi/kb\n  \"staking status\": true|false,  (boolean) if the wallet is staking or not\n  \"errors\": \"...\"           (string) any error messages\n}\n\nExamples:\n> divi-cli getinfo \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getinfo\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "getmininginfo" => "getmininginfo\n\nReturns a json object containing mining-related information.\nResult:\n{\n  \"blocks\": nnn,             (numeric) The current block\n  \"currentblocksize\": nnn,   (numeric) The last block size\n  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n  \"errors\": \"...\"          (string) Current errors\n  \"pooledtx\": n              (numeric) The size of the mem pool\n  \"testnet\": true|false      (boolean) If using testnet or not\n  \"chain\": \"xxxx\",         (string) current network name as defined in BIP70 (main, test, regtest)\n}\n\nExamples:\n> divi-cli getmininginfo \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getmininginfo\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "getnewaddress" => "getnewaddress ( \"account\" )\n\nReturns a new DIVI address for receiving payments.\nIf 'account' is specified (recommended), it is added to the address book \nso payments received with the address will be credited to 'account'.\n\nArguments:\n1. \"account\"        (string, optional) The account name for the address to be linked to. if not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n\nResult:\n\"diviaddress\"    (string) The new divi address\n\nExamples:\n> divi-cli getnewaddress \n> divi-cli getnewaddress \"\"\n> divi-cli getnewaddress \"myaccount\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getnewaddress\", \"params\": [\"myaccount\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "getreceivedbyaccount" => "getreceivedbyaccount \"account\" ( minconf )\n\nReturns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n\nArguments:\n1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n\nResult:\namount              (numeric) The total amount in DIVI received for this account.\n\nExamples:\n\nAmount received by the default account with at least 1 confirmation\n> divi-cli getreceivedbyaccount \"\"\n\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n> divi-cli getreceivedbyaccount \"tabby\" 0\n\nThe amount with at least 6 confirmation, very safe\n> divi-cli getreceivedbyaccount \"tabby\" 6\n\nAs a json rpc call\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getreceivedbyaccount\", \"params\": [\"tabby\", 6] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "help" => "help ( \"command\" )\n\nList all commands, or get help for a specified command.\n\nArguments:\n1. \"command\"     (string, optional) The command to get help on\n\nResult:\n\"text\"     (string) The help text\n",
        "listaccounts" => "listaccounts ( minconf includeWatchonly)\n\nReturns Object that has account names as keys, account balances as values.\n\nArguments:\n1. minconf          (numeric, optional, default=1) Only include transactions with at least this many confirmations\n2. includeWatchonly (bool, optional, default=false) Include balances in watchonly addresses (see 'importaddress')\n\nResult:\n{                      (json object where keys are account names, and values are numeric balances\n  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n  ...\n}\n\nExamples:\n\nList account balances where there at least 1 confirmation\n> divi-cli listaccounts \n\nList account balances including zero confirmation transactions\n> divi-cli listaccounts 0\n\nList account balances for 6 or more confirmations\n> divi-cli listaccounts 6\n\nAs json rpc call\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"listaccounts\", \"params\": [6] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "listreceivedbyaccount" => "listreceivedbyaccount ( minconf includeempty includeWatchonly)\n\nList balances by account.\n\nArguments:\n1. minconf      (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n2. includeempty (boolean, optional, default=false) Whether to include accounts that haven't received any payments.\n3. includeWatchonly (bool, optional, default=false) Whether to include watchonly addresses (see 'importaddress').\n\nResult:\n[\n  {\n    \"involvesWatchonly\" : \"true\",    (bool) Only returned if imported addresses were involved in transaction\n    \"account\" : \"accountname\",  (string) The account name of the receiving account\n    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n    \"confirmations\" : n           (numeric) The number of confirmations of the most recent transaction included\n    \"bcconfirmations\" : n         (numeric) The number of blockchain confirmations of the most recent transaction included\n  }\n  ,...\n]\n\nExamples:\n> divi-cli listreceivedbyaccount \n> divi-cli listreceivedbyaccount 6 true\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"listreceivedbyaccount\", \"params\": [6, true, true] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "setaccount" => "setaccount \"diviaddress\" \"account\"\n\nSets the account associated with the given address.\n\nArguments:\n1. \"diviaddress\"  (string, required) The divi address to be associated with an account.\n2. \"account\"         (string, required) The account to assign the address to.\n\nExamples:\n> divi-cli setaccount \"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\" \"tabby\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"setaccount\", \"params\": [\"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwg\", \"tabby\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "signmessage" => "signmessage \"diviaddress\" \"message\" \"input_format\" \"output_format\"\n\nSign a message with the private key of an address\n\nArguments:\n1. \"diviaddress\"    (string, required) The divi address to use for the private key.\n2. \"message\"        (string, required) The message to create a signature of.\n3. \"input_format\"   (string, optional) ['hex'] Message encoding format. Default plaintext\n4. \"output_format\"  (string, optional) ['hex'] Message encoding format. Default base64\n\nResult:\n\"signature\"          (string) The signature of the message encoded in base 64\n\nExamples:\n\nUnlock the wallet for 30 seconds\n> divi-cli walletpassphrase \"mypassphrase\" 30\n\nCreate the signature\n> divi-cli signmessage \"diviaddress\" \"my message\"\n\nVerify the signature\n> divi-cli verifymessage \"diviaddress\" \"signature\" \"my message\"\n\nAs json rpc\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"signmessage\", \"params\": [\"diviaddress\", \"my message\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "validateaddress" => "validateaddress \"diviaddress\"\n\nReturn information about the given divi address.\n\nArguments:\n1. \"diviaddress\"     (string, required) The divi address to validate\n\nResult:\n{\n  \"isvalid\" : true|false,         (boolean) If the address is valid or not. If not, this is the only property returned.\n  \"address\" : \"diviaddress\", (string) The divi address validated\n  \"ismine\" : true|false,          (boolean) If the address is yours or not\n  \"isscript\" : true|false,        (boolean) If the key is a script\n  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n  \"iscompressed\" : true|false,    (boolean) If the address is compressed\n  \"account\" : \"account\"         (string) The account associated with the address, \"\" is the default account\n}\n\nExamples:\n> divi-cli validateaddress \"diviaddress\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"validateaddress\", \"params\": [\"diviaddress\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "verifychain" => "verifychain ( numblocks )\n\nVerifies blockchain database.\n\nArguments:\n1. numblocks    (numeric, optional, default=288, 0=all) The number of blocks to check.\n\nResult:\ntrue|false       (boolean) Verified or not\n\nExamples:\n> divi-cli verifychain \n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"verifychain\", \"params\": [] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
        "verifymessage" => "verifymessage \"diviaddress\" \"signature\" \"message\"\n\nVerify a signed message\n\nArguments:\n1. \"diviaddress\"  (string, required) The divi address to use for the signature.\n2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n3. \"message\"         (string, required) The message that was signed.\n\nResult:\ntrue|false   (boolean) If the signature is verified or not.\n\nExamples:\n\nUnlock the wallet for 30 seconds\n> divi-cli walletpassphrase \"mypassphrase\" 30\n\nCreate the signature\n> divi-cli signmessage \"diviaddress\" \"my message\"\n\nVerify the signature\n> divi-cli verifymessage \"diviaddress\" \"signature\" \"my message\"\n\nAs json rpc\n> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"verifymessage\", \"params\": [\"diviaddress\", \"signature\", \"my message\"] }' -H 'content-type: text/plain;' http://127.0.0.1:51473/\n",
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
        for (_, name, line, _) in LIST {
            if let Some(text) = text(name) {
                assert_eq!(text.lines().next(), Some(*line), "{name}");
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
