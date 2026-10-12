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
| `encryptwallet`, `walletpassphrasechange`, `walletpassphrase`, `walletlock` | real wallet encryption: the mnemonic and every private key are AES-256-CBC encrypted under a random master key, which is sealed by a PBKDF2 key from the passphrase. Plaintext is deleted from the DB and compacted out. `getwalletinfo` reports real `encryption_status` and `unlocked_until`. Verified on a live regtest `irondivid`, including restart persistence |

Harness result on live testnet nodes (157 call rows): before these fixes MATCH 22 /
DIFFERS 69; after, **MATCH 47 / UNVERIFIED 8 / DIFFERS 40**. A later run on fully synced nodes (after the missing-key and error-code fixes below, commit `8965355`) gave **MATCH 49 / UNVERIFIED 10 / DIFFERS 36**, with no "missing in Rust" keys left except `getblock` `moneysupply`/`acc_checkpoint`. The `walletpassphrase`/`walletpassphrasechange`/`encryptwallet` encryption-state ordering and `listaccounts` default `""` account were fixed after that run and are covered by unit tests only. `bip38paperwallet` was also
round-tripped through `bip38decrypt` (right and wrong passphrase) on a live irondivid.

Final run (commit `a399431`, both nodes at the same testnet tip, Rust resynced from scratch): **MATCH 61 / UNVERIFIED 11 / DIFFERS 23**, with no key missing in Rust anywhere. Values compared live and identical: `getblock` `moneysupply` and `acc_checkpoint` at heights 1, 1000, 200000, 346000; `getlotteryblockwinners` (no arg and an explicit height); `spork show` and `spork active`. The 23 DIFFERS are Rust-only extra keys (harmless), documented deliberate deviations (`listbanned`, `loadwallet`, lenient `getrawtransaction`/`getmasternodewinners` args), wallet-state-dependent ordering in the harness (the C++ wallet was encrypted by an earlier mutating call, so `walletpassphrase*` codes differ), `setgenerate` (-32601 vs -1), and `startmasternode`.

## Still different (open)

**Missing (return -32601):** none.

**Implemented after the harness run (unit-tested only; regtest cannot mine over RPC):**
`signtransactionwithaddresskey` (SIGHASH_SINGLE over a `<pubkey> OP_CHECKSIG` dummy script, returns the scriptSig asm, like C++).
`invalidateblock`, `reconsiderblock`, `reverseblocktransactions` (`Chain::invalidate_block` /
`reconsider_block`: roll the tip back past the block, mark it and descendants failed, then
activate the best remaining valid chain; reconsider clears the flag on the block, its
ancestors and descendants). Error codes: missing block `-5`, wrong arg count `-1`, state
failure `-20`. `reverseblocktransactions` is invalidate then reconsider (the C++ flag that
corrupts the coin DB on purpose is not reproduced).

**Stubs / hardcoded:**
- `getpeerinfo`: now real per-peer `version`, `subver`, `services`, `lastsend`, `lastrecv`, `bytessent`, `bytesrecv`, `conntime`, `pingtime`, `startingheight`, `banscore`, `id` (live stats published by each connection). `inflight`, `synced_headers`, `synced_blocks`, `whitelisted` are still constants.
- Masternode subsystem: `signmnbroadcast`, `setupmasternode`, `broadcaststartmasternode`, `startmasternode`, `importmnbroadcast`, `listmnbroadcasts` and `verifymasternodesetup` are now real and use a byte-exact C++ `CMasternodeBroadcast`/`CMasternodePing` codec (`crates/divi-masternode/src/cpp_wire.rs`, message-signing hash `DarkNet Signed Message:\n`). Broadcasts are stored in `mnbroadcasts.json` in the datadir, `masternode.conf` is read from the datadir, and a valid broadcast is relayed to peers as raw `mnb` bytes. Unit-tested only; not yet compared against a C++ node. Known limits: inbound C++-format `mnb` handling (`divi-node/src/node.rs`, `divi-network/src/masternode_handler.rs`) still parses the older Rust format; `setupmasternode` generates a fresh key per call; the node never runs as a masternode, so `startmasternode` for a known alias returns the C++ controller-style failure and ping update is a no-op. `getmasternodewinners` has the C++ shape but every winner is `Unknown` (payment votes are not received); `getmasternodecount` lacks `inqueue/ipv4/ipv6/onion/obfcompat/stable` (reported as 0).
- `spork show|active` are now real (`84e27d3`/`a399431`): the 11 C++ spork names with the C++ defaults, received values override; two-arg form gives `Invalid spork name` / `failure`. Unit-tested.
- `getlotteryblockwinners` is now real: optional height (clamped to tip), C++ shape, candidates ranked with the consensus lottery score against the last lottery block. `decodescript` and `gettxout` also used a hardcoded mainnet address network; they now use the node's network.
- `getblock`: `acc_checkpoint` now present; `moneysupply` is recorded per block in the block index (trailing optional field, old databases still load) and shown only for blocks connected since that field was added, so an existing database shows it only after a resync/reindex. Genesis supply is 0, as in C++.
- `getaddressesbylabel` returns all addresses; `loadwallet` (multi-wallet), `allocatefunds`,
  rescan variants are stubs.
- `ban outdated`: peer versions are not tracked, returns an error.

**Shape differences (extras in Rust are harmless to clients; *missing* keys are bugs):**
`getblockchaininfo`, `getmempoolinfo`, `getmininginfo`, `gettxoutsetinfo`
(`bytes_serialized` missing), `getblock`, `getblockheader` (different shape),
`gettxout` (now has `scriptPubKey.asm` and `version`; `version` is a constant 1 because the UTXO set does not store tx version), `getrawtransaction` (`vin[].coinbase`
missing; C++ rejects a bool verbose arg with -1, Rust accepts it), `decodescript`
(`p2sh` missing), `getwalletinfo` (now has all C++ keys; `spendable_balance` equals `balance` and `vaulted_balance` is 0 until vault accounting is wired), `getstakingstatus`
(fixed: bool `staking status`, `stake split threshold`; the old string is kept as `staking status text`),
`getcoinavailability` (fixed: C++ `Vaulted`/`Stakable`/`Spendable`, verbose form with `AllVaults`/`NonVaults`; `Stakable` is approximated by mature non-vault coins), `listreceivedbyaccount` (`bcconfirmations`), `getmasternodestatus`.

**Param-handling / error-code differences:** the remaining per-method code differences
(`-3` type, `-5` invalid address, `-8` invalid parameter, `-13` unlock needed, `-15` wrong
encryption state, `-22` deserialization) are listed per method in the harness matrix.
`getnetworkinfo.protocolversion` is 70920 in Rust vs 70915 in C++ 3.0.0.

## Deliberate deviation

`getrawtransaction` accepts a bool `verbose` (C++ rejects it with -1) and `getmasternodewinners` accepts an integer count (C++ wants a string). Rust stays lenient: a superset of C++ behaviour that cannot break a client written for C++.

`encryptwallet`: C++ stops the daemon after encrypting (to rebuild the keypool). Rust keeps
running and leaves the wallet locked. Rust has no keypool, so `getnewaddress` on a locked
encrypted wallet returns -13 until `walletpassphrase`.

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

1. ~~Masternode subsystem RPCs~~ done (see above for limits); remaining: C++-format inbound `mnb`/`mnp` handling and payment votes.
2. ~~`invalidateblock` family~~ done.
3. ~~`getblock` `moneysupply`/`acc_checkpoint`~~ done (unit and chain tests; not yet compared against C++ in a harness run).
4. ~~Error-code order differences (`sendtoaddress`, `setaccount`, `importaddress`, `removevault`, `lockunspent`) and `ban` with a bad IP~~ done (unit-tested in `error_code_order_matches_cpp`).
5. Re-run the harness with a funded fixture wallet on both sides to verify the list-returning wallet RPCs.
