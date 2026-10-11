# RPC parity audit: IronDivi vs C++ Divi

Why this exists: IronDivi's RPC surface was reported as fully implemented. A live
comparison shows it was not. This is the record of that comparison and what is left.

## Method

- **C++ reference:** `DiviProject/Divi` at `9e2f76c4408380e72f6e369fff3882ed13667a42`
  (2023-07 master). The deployed daemon reports version `3.0.0.0`. A source copy
  lives at `~/code/divi-cpp-ref` (not in this repo); re-clone the 3.0.0 tag to reproduce.
- **Harness:** `tools/rpc-parity/` (`rpc_parity.py`, `report.py`). It calls the same RPC on a
  C++ `divid` and an `irondivid` synced to the same testnet, and diffs error codes and
  JSON shape (keys + types). Mutating methods are only called with deliberately invalid
  arguments. Wallets on both sides were empty, so wallet-method *shapes* that return
  lists are unverified (`UNVERIFIED` rows).
- Run it against a **throwaway** C++ node, never a production one (see "C++ crash bugs").

## Status after this audit (commits `299fcd0`, `e5bc492`, `544d915`)

Implemented or fixed:

| Item | Change |
|---|---|
| `getchaintips` | real implementation: side branches, `branchlen`, C++ status values |
| `ban`, `bip38paperwallet`, `getinvalid`, `setmocktime` | were missing, now dispatched (`setmocktime` is an honest error: no mock clock) |
| `disconnectnode` | bug: disconnected the *first* peer regardless of address; now the exact peer |
| `getinfo` | real `moneysupply` (UTXO sum, cached per tip), string `version`, `walletversion` |
| error codes | usage/internal errors now `-1` like C++ (were JSON-RPC `-32602`/`-32603`) |
| `getrawmempool true` | returns the verbose object keyed by txid |
| `listmasternodes` | returns a bare array |
| `getaddednodeinfo` | arg order is `dns ( "node" )`; unknown node gives `-24` |
| `getnetworkinfo`, `getpeerinfo`, `mnsync status` | missing fields added |

Harness result on live testnet nodes (157 call rows): before these fixes MATCH 22 /
DIFFERS 69; after, **MATCH 47 / UNVERIFIED 8 / DIFFERS 40**. `bip38paperwallet` was also
round-tripped through `bip38decrypt` (right and wrong passphrase) on a live irondivid.

## Still different (open)

**Missing (return -32601):**
`invalidateblock`, `reconsiderblock`, `reverseblocktransactions` need a chain-engine
"invalidate then reorganise" path (`mark_block_failed`, `disconnect_block`,
`reorganize_chain` exist in `divi-storage/src/chain.rs`, but `activate_best_chain` only
reorgs to a heavier chain). `signtransactionwithaddresskey` not started.
`encryptwallet`/`walletpassphrasechange`: a Rust wallet can never become encrypted (no
encryption metadata is stored; the mnemonic is plaintext; `WalletDb::change_passphrase` is
a no-op). This needs a design decision, not a fake RPC.

**Stubs / hardcoded:**
- `getpeerinfo`: `version`, `subver`, `lastsend`, `lastrecv`, `bytessent`, `bytesrecv`,
  `conntime`, `pingtime`, `startingheight`, `banscore` are constants; `id` is the list index.
  Needs per-peer stat tracking in `PeerHandle`.
- Masternode subsystem: `listmnbroadcasts`, `startmasternode`, `setupmasternode`,
  `broadcaststartmasternode`, `signmnbroadcast`, `importmnbroadcast`,
  `verifymasternodesetup` return "not implemented"; `getmasternodewinners` uses height 0 and
  the wrong shape (`height`/`payee` vs C++ `nHeight`/`winner`); `getmasternodecount` lacks
  `inqueue/ipv4/ipv6/onion/obfcompat/stable`; `spork show|active` stubbed;
  `getlotteryblockwinners` stubbed (and requires an argument C++ does not).
- `getblock`: no `moneysupply` or `acc_checkpoint` (needs a block-index schema change).
- `getaddressesbylabel` returns all addresses; `loadwallet` (multi-wallet), `allocatefunds`,
  rescan variants are stubs.
- `ban outdated`: peer versions are not tracked, returns an error.

**Shape differences (extras in Rust are harmless to clients; *missing* keys are bugs):**
`getblockchaininfo`, `getmempoolinfo`, `getmininginfo`, `gettxoutsetinfo`
(`bytes_serialized` missing), `getblock`, `getblockheader` (different shape),
`gettxout` (`scriptPubKey.asm`, `version` missing), `getrawtransaction` (`vin[].coinbase`
missing; C++ rejects a bool verbose arg with -1, Rust accepts it), `decodescript`
(`p2sh` missing), `getwalletinfo` (now has all C++ keys; `spendable_balance` equals `balance` and `vaulted_balance` is 0 until vault accounting is wired), `getstakingstatus`
(`stake split threshold` missing; `staking status` is a string vs bool),
`getcoinavailability`, `listreceivedbyaccount` (`bcconfirmations`), `getmasternodestatus`.

**Param-handling / error-code differences:** the remaining per-method code differences
(`-3` type, `-5` invalid address, `-8` invalid parameter, `-13` unlock needed, `-15` wrong
encryption state, `-22` deserialization) are listed per method in the harness matrix.
`getnetworkinfo.protocolversion` is 70920 in Rust vs 70915 in C++ 3.0.0.

## Deliberate deviation

`listbanned`: C++ returns `{"banned:": "<string>"}` (stray colon, value is a pre-formatted
string: a C++ bug). Rust returns a proper array.

## Not in C++ (Rust-only methods)

`allocatefunds`, `bip38encrypt`, `disconnectnode`, `estimatefee`, `estimatepriority`,
`estimatesmartfee`, `getaddressbalance`, `getaddressdeltas`, `getaddresshistory`,
`getaddressinfo`, `getaddresstxids`, `getaddressutxos`, `getaddressesbylabel`,
`getimmaturebalance`, `getkeypoolsize`, `getlitewalletinfo`, `getlogconfig`,
`getmintinginfo`, `getpeerscores`, `getspentinfo`, `gettxindex`, `rescanblockchain`,
`reservebalance`, `setban`, `setlogconfig`, `setstaking`, `signrawtransactionwithwallet`,
`validateaddresses`. (`setban` is Rust's spelling of C++ `ban`; both now exist.)

## C++ divid 3.0.0 crash bugs found by the harness

These abort the C++ daemon; do not call them on a production node:
- `verifymasternodesetup` with no wallet: assertion in `CRPCTable::execute`
  (`rpcserver.cpp:1045`).
- `generateblock`: assertion `blockFactory` (`rpcmining.cpp:169`).
- `signtransactionwithaddresskey` with no arguments: silent daemon exit.

## Next

1. Per-peer stats for `getpeerinfo`.
2. Masternode subsystem RPCs (largest remaining gap).
3. `invalidateblock` family (engine work).
4. `encryptwallet` design.
5. Fill the missing keys listed under "Shape differences".
6. Re-run the harness with a funded fixture wallet on both sides to verify the list-returning wallet RPCs.
