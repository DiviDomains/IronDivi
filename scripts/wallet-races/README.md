# Wallet calls that overlap, next to Divi Core

The other wallet scripts send one call at a time to a quiet node. This one makes many clients call the wallet at once,
while the unlock timer runs out, `walletlock` comes, coins are locked or blocks arrive. It checks what each race
leaves behind on Divi Core 3.0.0 `divid` and on irondivid.

divid runs one wallet call at a time. `CRPCTable::execute` takes `cs_main` for every call that is not thread-safe, the
whole wallet table among them (rpcserver.cpp:1060-1094, table :430-464), and a block's wallet update runs under
`cs_main` too. So where an outcome does not depend on timing, irondivid's must match divid's. Where it does depend on
timing (which send wins against a `walletlock`), both programs must still leave a wallet that makes sense.

`run.sh` prints one line for each row:

- `PASS`: as divid, and every check held on both;
- `KNOWN`: differs, and the difference is listed below with the reason (none at present);
- `FAIL`: differs, a check did not hold, or a `KNOWN` row now matches divid.

Lines starting `#` show an outcome that depends on timing; it is printed but not compared. The run ends with
`FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15 minutes).

```sh
scripts/wallet-races/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/wallet-races/run.sh target/release ~/divi-3.0.0/bin 54300 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+9` (p2p and RPC of five nodes), bound to 127.0.0.2
  (`WALLET_RACES_HOST` to change it). The nodes reach only the miner; the two keypool nodes dial
  `<port-base>+49`, where nothing listens.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 80 seconds and is stopped after 15 minutes. However it ends, every node is stopped and its
directory deleted. It needs bash and python3 (standard library only).

`WALLET_RACES_INJECT=<row name>` changes irondivid's side of that row before it is compared, to show that a difference
is caught.

Secrets:
- The phrase is read from divid's `dumphdinfo` and handed to irondivid in its environment (`WALLET_MNEMONIC`).
- The wallet passphrase is random, made by the run into a 0600 file in its directory. It goes only into RPC request
  bodies, never onto a command line or into the output.

## Nodes

| node | what |
|---|---|
| miner | divid; mines every block and pays every coin the wallets get |
| divid | divid; the wallet under test, dialling the miner |
| irondivid | irondivid from divid's phrase; the same wallet, dialling the miner |
| divid-keypool, irondivid-keypool | `-keypool=4`, each a wallet of its own, for the `getnewaddress` case |

Every node runs with `staking=0` and `rpcthreads=16`.

## Turns

Each case runs as a turn on divid and then as the same turn on irondivid:

1. The wallet's coins from earlier turns are swept to the miner in one raw transaction, so that each turn starts from
   the coins it is funded with and nothing else.
2. The miner sends the turn's coins (at most 30 sends a block, since its change is unconfirmed until then), and a block
   confirms them.
3. The clients start together, released by a barrier, each on its own connection. A call's delay after the release
   staggers it where the case says so.
4. The checks below, then a block that mines the turn.
5. Both wallets, one phrase on one chain, must agree: the balance, the coins (`listunspent`) and the transaction list
   (`listtransactions`: txid, category, amount and vout).

The checks of every send race:
- every refusal is one the case allows (below), with divid's code and text;
- no txid was handed to two callers, and no coin is spent by two accepted sends;
- every accepted send is in the wallet, and in the mempool or a block;
- no send is in the wallet that no caller was given: nothing half-made stays;
- after the block, the coins left equal the coins before plus the accepted sends' amounts (each amount includes the
  fee in both programs), and `getbalance` equals `listunspent`.

## Cases

| case | outcome compared | refusals allowed |
|---|---|---|
| 8 parallel `sendtoaddress` of 9.9, 5 coins of 10 | yes: 5 made, 3 refused | -6 `Insufficient funds: …(total requested) is greater than …(total available)` (rpcwallet.cpp:752-761), -4 `Insufficient funds to meet coin selection algorithm requirements.` (wallet.cpp:1777-1780) |
| 32 parallel `sendtoaddress` of 9.9, 20 coins of 10 | yes: 20 made, 12 refused | as above |
| 3 `sendtoaddress` of 4 and 3 `sendmany` of 2 + 2, 3 coins of 10 | yes: how many made, and the kinds refused | as above |
| `getnewaddress` from 16 clients: 64 unencrypted, 16 locked (the pool runs out, -12 `Error: Keypool ran out, please call keypoolrefill first`, rpcwallet.cpp:305-307), 64 unlocked | yes: the replies and `keypoolsize` | — |
| 16 sends of 4 and 3 readers (`listunspent`, `listunspent 0`, `getbalance`, `getunconfirmedbalance`, `listtransactions`) while the miner makes 5 blocks | no | the insufficient-funds pair. Every read must hold on its own: no coin listed twice, none under its minconf, no balance or coin sum above the coins before the race, no `listtransactions` entry twice, every confirmed entry with a block |
| 8 sends of 4 while `lockunspent` locks 2 coins and unlocks 2 others, with 2 locked throughout | yes: the coins locked afterwards | the insufficient-funds pair. A coin locked throughout is never spent; a coin locked during the race only by a send made before the lock was answered; a coin unlocked during the race only by a send still running when the unlock was asked. `listlockunspent` always holds the coins locked throughout, and afterwards exactly the coins locked before and during the race |
| 8 sends of 9.5 from coins of 0.25 (some forty inputs each) with a `walletlock` 0.03 s in | no | -13 `Error: Please enter the wallet passphrase with walletpassphrase first.` (rpcserver.cpp:1124-1128); -4 `Error: Wallet locked, unable to create transaction!` (rpcwallet.cpp:763-768). The wallet is locked afterwards |
| 12 sends of 9.5 from coins of 1, one every 0.1 s, after `walletpassphrase` for 1 s | no | as above; no send made 1.5 s or more after the unlock is accepted, and the wallet is locked afterwards |
| 4 sends on each wallet, then both nodes stopped and started at once | yes: each node's balance, unconfirmed balance and `listunspent 0` as before the stop | — |

The `walletlock` case shows that a send either completes or is refused, but a lock seldom lands in the middle of a send
here. `walletlock_during_a_send_comes_before_or_after_it` in crates/divi-rpc/tests/wallet_races.rs pins that moment.

## KNOWN differences

None. The window below is irondivid's, but no case here can reach it:

- Between a block entering the chain and its wallet update, irondivid's wallet calls read the chain's new height
  against the wallet before the block (`current_height`, crates/divi-rpc/src/wallet.rs:943-950; the wallet update
  in bin/irondivid/src/main.rs:1896-1928). divid connects the block and updates its wallet under `cs_main`
  (connectTip, ChainTipManager.cpp:105-150, the wallet told at :150).
- The difference shows only when a block spends a wallet coin from elsewhere: another wallet holding the same keys,
  or a stake. A send in the window can then pick that coin and be refused by the mempool.
- No case here has a block spend a coin of the wallet under test that the wallet did not send itself.
