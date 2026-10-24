# Replies of the divid calls no other script covers, next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain.
It makes the calls of divid's command table that no other replies script makes, and compares the replies field by
field: good arguments, wrong arguments, and the effect of a call that changes state, read back with another call.
Then both nodes start again, fresh, without a wallet, for the refusals there. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with a count of each and `FAILS <n>`. The exit code is the number of FAILs (255: usage error,
interrupted, or over 10 minutes).

```sh
scripts/uncovered-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/uncovered-replies/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's). Both
  pairs of nodes use the same four ports, one pair after the other.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end. Give an
  absolute path.

A run takes 15 to 50 seconds and is stopped after 10 minutes. However it ends, every node is stopped and its
directory deleted. Needs bash and python3 (standard library only). The phrase is read from divid's `dumphdinfo`
reply and handed to irondivid in its environment (`WALLET_MNEMONIC`). It is never printed, written to a file or put
on a command line. RPC passwords are made for the run and written only to each node's mode-600 `divi.conf`.

## Which calls this script makes

The table below is divid's command table (`vRPCCommands`, `divi/src/rpcserver.cpp:324-467`, at v3.0.0, commit
9e2f76c), with the scripts that call each entry. The list was made with a search for the call's name as a quoted
string in `scripts/*/*.py` and `scripts/*/*.sh` on integration 40fb768, plus:
- `keys-replies*`: `scripts/keys-replies/check.py` on `test/keys-replies` (535c6b9);
- `accounts-replies**`: the calls B11's accounts-replies item lists (`B11-accounts-replies.md`).

No `test/http-replies` branch was in the repository when the list was made, so none of its calls are counted.
`invalidateblock` and `reconsiderblock` are in divid's table twice (lines 358-359 and 387-388).

This script covers:
- the five calls no script makes: `reverseblocktransactions`, `getinvalid`, `signtransactionwithaddresskey`,
  `setmocktime`, `loadwallet`;
- the two only `swap-rpc` makes, which does not compare replies with divid: `getrawchangeaddress`,
  `listlockunspent`.

divid's table has no spork-only, lottery-only, treasury or budget call that no script makes. `spork`, `mnsync` and
the masternode calls are made by masternode-replies and net-replies, and `getlotteryblockwinners` by index-replies.

| rpcserver.cpp | category | call | called by |
|---|---|---|---|
| 329 | control | `getinfo` | chain-replies, cli-replies, index-replies, keys-replies*, masternode-replies, net-replies, raw-replies, restart-options, unclean-stop, unlock-send, util-replies, vault-replies, wallet-replies |
| 330 | control | `help` | cli-replies, masternode-replies, util-replies |
| 331 | control | `stop` | chain-replies, cli-replies, index-replies, keys-replies*, masternode-replies, net-replies, raw-replies, restart-options, swap-rpc, unclean-stop, unlock-send, util-replies, vault-replies, wallet-replies |
| 334 | network | `getnetworkinfo` | chain-replies, cli-replies, index-replies, keys-replies*, net-replies, raw-replies, restart-options, swap-rpc, unclean-stop, util-replies, vault-replies, wallet-replies |
| 335 | network | `addnode` | net-replies, unclean-stop |
| 336 | network | `getaddednodeinfo` | net-replies |
| 337 | network | `getconnectioncount` | net-replies, swap-rpc |
| 338 | network | `getnettotals` | net-replies |
| 339 | network | `getpeerinfo` | net-replies |
| 340 | network | `ping` | net-replies |
| 343 | blockchain | `getblockchaininfo` | chain-replies, cli-replies, swap-rpc |
| 344 | blockchain | `getbestblockhash` | chain-replies, cli-replies, index-replies, keys-replies*, masternode-replies, mining-replies, raw-replies, restart-options, swap-rpc, unclean-stop, util-replies, vault-replies, wallet-replies |
| 345 | blockchain | `getblockcount` | chain-replies, cli-replies, index-replies, keys-replies*, masternode-replies, mining-replies, net-replies, raw-replies, restart-options, swap-rpc, unclean-stop, unlock-send, util-replies, vault-replies, wallet-replies |
| 346 | blockchain | `getlotteryblockwinners` | index-replies |
| 347 | blockchain | `getblock` | chain-replies, cli-replies, raw-replies, swap-rpc, vault-replies |
| 348 | blockchain | `getblockhash` | chain-replies, cli-replies, raw-replies, restart-options, swap-rpc, unclean-stop, vault-replies, wallet-replies |
| 349 | blockchain | `getblockheader` | chain-replies, swap-rpc |
| 350 | blockchain | `getchaintips` | chain-replies |
| 351 | blockchain | `getdifficulty` | chain-replies, cli-replies, util-replies |
| 352 | blockchain | `getmempoolinfo` | mining-replies |
| 353 | blockchain | `getrawmempool` | chain-replies, cli-replies, index-replies, masternode-replies, mining-replies, raw-replies, unclean-stop, util-replies, vault-replies, wallet-replies |
| 354 | blockchain | `gettxout` | chain-replies, cli-replies, swap-rpc |
| 355 | blockchain | `gettxoutsetinfo` | chain-replies, unclean-stop |
| 356 | blockchain | `verifychain` | chain-replies, cli-replies, util-replies |
| 357 | blockchain | `reverseblocktransactions` | **uncovered-replies** |
| 358 | blockchain | `invalidateblock` | chain-replies |
| 359 | blockchain | `reconsiderblock` | chain-replies |
| 360 | getinvalid | `getinvalid` | **uncovered-replies** |
| 363 | mining | `getmininginfo` | cli-replies, mining-replies, util-replies |
| 364 | mining | `prioritisetransaction` | mining-replies |
| 368 | generating | `setgenerate` | chain-replies, cli-replies, index-replies, keys-replies*, masternode-replies, mining-replies, net-replies, raw-replies, restart-options, swap-rpc, unclean-stop, unlock-send, util-replies, vault-replies, wallet-replies |
| 369 | generating | `generateblock` | mining-replies |
| 373 | rawtransactions | `createrawtransaction` | chain-replies, cli-replies, index-replies, mining-replies, raw-replies, restart-options, swap-rpc, unlock-send |
| 374 | rawtransactions | `decoderawtransaction` | chain-replies, raw-replies, restart-options, swap-rpc |
| 375 | rawtransactions | `decodescript` | chain-replies, raw-replies |
| 376 | rawtransactions | `getrawtransaction` | chain-replies, cli-replies, index-replies, mining-replies, raw-replies, restart-options, swap-rpc, unclean-stop, vault-replies |
| 377 | rawtransactions | `sendrawtransaction` | chain-replies, index-replies, mining-replies, raw-replies, restart-options, swap-rpc |
| 378 | rawtransactions | `signtransactionwithaddresskey` | **uncovered-replies** |
| 379 | rawtransactions | `signrawtransaction` | chain-replies, index-replies, mining-replies, raw-replies, restart-options, swap-rpc, unlock-send |
| 382 | util | `createmultisig` | raw-replies, util-replies |
| 383 | util | `validateaddress` | chain-replies, cli-replies, masternode-replies, raw-replies, swap-rpc, util-replies, vault-replies |
| 384 | util | `verifymessage` | util-replies |
| 387 | hidden | `invalidateblock` | chain-replies |
| 388 | hidden | `reconsiderblock` | chain-replies |
| 389 | hidden | `setmocktime` | **uncovered-replies** |
| 392 | divi | `allocatefunds` | masternode-replies |
| 393 | divi | `listmasternodes` | masternode-replies, net-replies |
| 394 | divi | `getmasternodecount` | masternode-replies, net-replies |
| 395 | divi | `setupmasternode` | masternode-replies |
| 396 | divi | `signmnbroadcast` | masternode-replies |
| 397 | divi | `verifymasternodesetup` | masternode-replies |
| 398 | divi | `broadcaststartmasternode` | masternode-replies |
| 399 | divi | `startmasternode` | masternode-replies |
| 400 | divi | `getmasternodestatus` | masternode-replies, net-replies |
| 401 | divi | `getmasternodewinners` | masternode-replies |
| 402 | divi | `importmnbroadcast` | masternode-replies |
| 403 | divi | `listmnbroadcasts` | masternode-replies |
| 405 | divi | `mnsync` | masternode-replies, net-replies |
| 406 | divi | `spork` | masternode-replies, net-replies, restart-options, unclean-stop |
| 407 | divi | `ban` | net-replies |
| 408 | divi | `clearbanned` | net-replies |
| 409 | divi | `listbanned` | net-replies |
| 412 | addressindex | `getaddresstxids` | index-replies |
| 413 | addressindex | `getaddressdeltas` | index-replies |
| 414 | addressindex | `getaddressbalance` | index-replies, unclean-stop |
| 415 | addressindex | `getaddressutxos` | index-replies, swap-rpc |
| 417 | blockchain | `getspentinfo` | index-replies, unclean-stop |
| 420 | wallet | `addmultisigaddress` | raw-replies |
| 421 | wallet | `backupwallet` | keys-replies* |
| 422 | wallet | `dumpprivkey` | keys-replies*, raw-replies, swap-rpc, unclean-stop, unlock-send |
| 423 | wallet | `dumphdinfo` | chain-replies, cli-replies, keys-replies*, raw-replies, swap-rpc, unlock-send, util-replies, vault-replies, wallet-replies |
| 426 | wallet | `encryptwallet` | keys-replies*, swap-rpc, unclean-stop, unlock-send, vault-replies |
| 427 | wallet | `getaccountaddress` | accounts-replies** |
| 428 | wallet | `getaccount` | accounts-replies**, cli-replies |
| 429 | wallet | `getaddressesbyaccount` | accounts-replies**, cli-replies, keys-replies*, raw-replies, wallet-replies |
| 430 | wallet | `getbalance` | cli-replies, masternode-replies, unclean-stop, unlock-send, vault-replies, wallet-replies |
| 431 | wallet | `getnewaddress` | chain-replies, cli-replies, index-replies, keys-replies*, masternode-replies, mining-replies, raw-replies, restart-options, swap-rpc, unclean-stop, unlock-send, util-replies, vault-replies, wallet-replies |
| 432 | wallet | `getrawchangeaddress` | swap-rpc, **uncovered-replies** |
| 433 | wallet | `getreceivedbyaccount` | accounts-replies**, wallet-replies |
| 434 | wallet | `getreceivedbyaddress` | wallet-replies |
| 435 | wallet | `getstakingstatus` | unlock-send |
| 436 | wallet | `gettransaction` | swap-rpc, vault-replies, wallet-replies |
| 437 | wallet | `getunconfirmedbalance` | wallet-replies |
| 438 | wallet | `getwalletinfo` | keys-replies*, swap-rpc, unclean-stop, unlock-send, vault-replies, wallet-replies |
| 439 | wallet | `loadwallet` | **uncovered-replies** |
| 440 | wallet | `importprivkey` | keys-replies* |
| 441 | wallet | `importaddress` | keys-replies*, swap-rpc, util-replies, wallet-replies |
| 442 | wallet | `keypoolrefill` | keys-replies* |
| 443 | wallet | `listaccounts` | accounts-replies**, cli-replies, wallet-replies |
| 444 | wallet | `listlockunspent` | swap-rpc, **uncovered-replies** |
| 445 | wallet | `listreceivedbyaccount` | accounts-replies**, wallet-replies |
| 446 | wallet | `listreceivedbyaddress` | wallet-replies |
| 447 | wallet | `listsinceblock` | wallet-replies |
| 448 | wallet | `listtransactions` | vault-replies, wallet-replies |
| 449 | wallet | `listunspent` | index-replies, mining-replies, restart-options, swap-rpc, unlock-send, vault-replies, wallet-replies |
| 450 | wallet | `lockunspent` | chain-replies, raw-replies, swap-rpc |
| 451 | wallet | `sendfrom` | wallet-replies |
| 452 | wallet | `sendmany` | chain-replies, unclean-stop, wallet-replies |
| 453 | wallet | `sendtoaddress` | chain-replies, cli-replies, index-replies, masternode-replies, raw-replies, swap-rpc, unclean-stop, unlock-send, util-replies, wallet-replies |
| 454 | wallet | `fundvault` | chain-replies, vault-replies |
| 455 | wallet | `reclaimvaultfunds` | vault-replies |
| 456 | wallet | `debitvaultbyname` | vault-replies |
| 457 | wallet | `removevault` | vault-replies |
| 458 | wallet | `addvault` | vault-replies |
| 459 | wallet | `getcoinavailability` | vault-replies |
| 460 | wallet | `setaccount` | accounts-replies**, cli-replies, keys-replies*, util-replies, wallet-replies |
| 461 | wallet | `signmessage` | unlock-send, util-replies |
| 462 | wallet | `walletlock` | keys-replies*, swap-rpc, unlock-send |
| 463 | wallet | `walletpassphrasechange` | unclean-stop, unlock-send |
| 464 | wallet | `walletpassphrase` | keys-replies*, swap-rpc, unclean-stop, unlock-send |

## Nodes and steps

divid listens; irondivid dials it (`connect=`), so both see one chain, and both wallets own the same keys. Both run
with `staking=0`.

1. divid mines 40 blocks, whose coinbases are both wallets'.
2. `getinvalid`: none, `all`, another text, a number, two arguments.
3. `getrawchangeaddress`: none twice, one argument (not read), two arguments. Then `validateaddress` of each node's
   change address, and `getaccount` of divid's.
4. `listlockunspent`:
   - with nothing locked;
   - after `lockunspent false` on three coins;
   - after `lockunspent true` on one of them;
   - after unlocking all;
   - with an argument.
5. `signtransactionwithaddresskey` on a raw transaction of two of the wallets' coins and one output:
   - input 0, and input 1 with its coin's key and with the other coin's key (input 1 has no output of its index);
   - an address not in the wallet, and not an address;
   - hex that is not hex, and hex that is not a transaction;
   - the index as text and as a real; the address and the hex as numbers;
   - four arguments.
6. `reverseblocktransactions`:
   - no argument, two arguments, a number, an unknown block, not hex;
   - then the tip on both nodes, followed by `getblockcount` and `getbestblockhash`, and whether the tip is the
     reversed block's parent;
   - divid mines two more blocks: `getblockcount`, and `getblockhash` at the reversed height.
7. `setmocktime`:
   - a text, a real, no argument, two arguments;
   - the tip's time + 1000 s on both, then each node mines one block: its time minus the mock time;
   - `0` to give the clock back.
8. `loadwallet` (last, since divid switches its wallet): no argument, two arguments, a number, a file name.
9. Both nodes stop. A fresh pair starts with `disablewallet=1` (genesis only, as divid cannot mine without a wallet):
   - `getrawchangeaddress`, `listlockunspent`, `loadwallet`, `signtransactionwithaddresskey`;
   - `getinvalid`, `setmocktime` with a text, `reverseblocktransactions` of an unknown block.

How a row compares:
- Both must have the same outcome: a result, or an error with the same code and message.
- For a result, every field name, type and value must match, and list items must come in divid's order.
- divid answers a wrong argument count with the call's help text. That text is not compared; both must refuse with -1.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

- **`signtransactionwithaddresskey` input index past the inputs:** not sent to divid. divid's SignForOutput reads
  the input past the list (rpcrawtransaction.cpp:589) and divid aborts. irondivid answers -4 "Unable to sign for
  input"; the row shows it only.
- **`signtransactionwithaddresskey` with two, one or no argument:** not sent to divid. divid has no argument count
  check and reads `params[0..2]` (rpcrawtransaction.cpp:566-572). With two or one argument it reads past the list
  and answers with whatever it finds there (for example "value is type obj, expected int"); with none it stops on a
  segmentation fault. irondivid answers -1 with the call's usage; the rows show it only.
- **`setmocktime`, the next block's time, and `setmocktime 0`:** irondivid has no mock clock. Each part reads the
  system clock (block times, mempool, peers), so the call is refused on regtest too, and a block irondivid mines
  keeps the real time. divid sets one clock for the whole node (SetMockTime, rpcmisc.cpp:526-541). The argument
  errors (a text, a real, a wrong count) are the same as divid's.
- **`loadwallet` a file:** irondivid opens one wallet at start and keeps it; the call is refused with a message
  naming `--wallet` and the wallet in use (docs/divid-differences.md R2). divid switches to the named wallet. The
  argument errors are the same as divid's.

No other row differs from divid.

## Proving a difference is caught

`UNCOVERED_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared. For example,
`UNCOVERED_REPLIES_INJECT='getinvalid'` makes that row print `FAIL`, and the run exits 1.
`UNCOVERED_REPLIES_DUMP=<dir>` writes both replies of every differing row to `<dir>`, for looking into a FAIL.
