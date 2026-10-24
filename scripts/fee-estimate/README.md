# Fee settings next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest, both with wallets made from the same phrase,
and compares, case by case:

- the fee options at start: `-paytxfee`, `-mintxfee`, `-minrelaytxfee` and `-maxtxfee`, each with a good value, 0, a
  very high value and a value that is not an amount (`divi/src/init.cpp:823-845`);
- what `getinfo` and `getwalletinfo` report (`relayfee`, `paytxfee`) at each setting;
- the fee the wallet pays for `sendtoaddress`, `sendmany` and `fundvault` at each setting;
- what `sendrawtransaction` takes and refuses, with the exact reject code and text;
- a `fee_estimates.dat` across a restart: none, one that is corrupt, the corrupt one kept, one removed.

Divi Core 3.0.0 has no `estimatefee`, `estimatepriority` or `settxfee` call, and it never makes its fee estimator
(`divi/src/txmempool.cpp:50` is commented out), so it neither reads nor writes `fee_estimates.dat`. `estimatefee` and
`settxfee` are compared in `scripts/util-replies` and `scripts/keys-replies`; `estimatepriority` once here.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 10 minutes).

```sh
scripts/fee-estimate/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/fee-estimate/run.sh target/release ~/divi-3.0.0/bin 54100 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 3 minutes and is stopped after 10. However it ends, both nodes are stopped and their directories
deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run and kept in
the 0600 `divi.conf`. The wallet phrase is read from divid's `dumphdinfo` and handed to irondivid in its environment
(`WALLET_MNEMONIC`); it is never printed or put on a command line.

## Nodes

divid mines 60 blocks and irondivid follows. Five addresses of divid's wallet get the same account on irondivid's,
and the oldest coins are listed. Then irondivid is restarted with no peer (`connect=127.0.0.2:1`). From there each
node sees only its own sends, so both wallets keep the same coins and choose the same ones, and a raw transaction
one node takes is not relayed to the other.

The raw transactions are built here and signed by divid's `signrawtransaction`. The twelve coins they spend are
locked with `lockunspent` on both nodes after every start, so the wallets' own sends never take them.

Sizes are shown but not compared: a signature is 71 or 72 bytes, so the same send may differ by a byte per input.
The fee is compared.

## Rows

| step | rows (each on both nodes) |
|---|---|
| defaults | `estimatepriority 2` (see KNOWN); `getinfo` `relayfee` 0.0001; `paytxfee` (see KNOWN) |
| wallet sends at 10,000 sat/kB | `sendtoaddress 10` (2,260 sat), `sendmany` 1+2+3 (2,940), `sendmany` to 30 addresses (12,120), `fundvault` owner:manager 100 (2,510), `sendtoaddress 4000` with several inputs (6,700). The fee is the relay fee for the estimated size, at most `-maxtxfee` (`divi/src/wallet.cpp:1559-1562`) |
| `sendrawtransaction`, default `-maxtxfee` (100 DIVI, `divi/src/defaultValues.h:34`) | a 150 DIVI fee: -26 `Fees being paid are in excess of maximum fee, but fee override is not provided` (`divi/src/rpcrawtransaction.cpp:882`); with `allowhighfees` taken; a 99 DIVI fee taken |
| `sendrawtransaction` rejects | a coin a mempool transaction spends: -25 with an empty text; a coin spent in a block: -26 `Unknown inputs being spent` (`:875-881`); a transaction in a block: -27 `transaction already in block chain` |
| blocks | transactions at 20,000, 50,000, 100,000 and 500,000 sat/kB, then 3 blocks on each node |
| `fee_estimates.dat` | start with none; none written by the clean stop; start with a corrupt one, again with it kept, then with it removed: both start, and neither log names the file |
| `-minrelaytxfee=0.001` | `relayfee` 0.001; the sends above pay ten times as much (22,600, 29,400, 25,100 sat); a raw transaction of an old coin paying 0.0002 is taken (free on priority) |
| `-maxtxfee=0.0002` | `relayfee` unchanged; `sendtoaddress 10` (2,260 sat) is sent; `sendtoaddress 20000`, whose many inputs would cost more than 0.0002: -4 `Insufficient funds to meet coin selection algorithm requirements.` (`divi/src/MinimumFeeCoinSelectionAlgorithm.cpp:97`); a raw transaction paying 0.001: -26 as above, taken with `allowhighfees`, then sent again while in the mempool: its txid (the fee is not checked again, `:875`); a spend of its output, in the mempool only, paying 0.001: -26 (the mempool's outputs count, `:810-826`), taken with `allowhighfees` |
| start options | `-paytxfee` and `-mintxfee` = 0.001, 0, 1000, abc: start (no code in divid 3.0.0 reads them; `paytxfee` is named only in help texts, `divi/src/rpcmisc.cpp:123` and `divi/src/LicenseAndInfo.cpp:143`); after `-paytxfee=0.001` and `-mintxfee=0.001` the wallet still pays 2,260 sat. `-minrelaytxfee` = 0.001, 10: start; 0, abc: refused. `-maxtxfee` = 0.5, 10000: start, 10000 with `Warning: -maxtxfee is set very high!` in the log; 0: refused, `(must be at least the minrelay fee of 0.00010000 DIV/kB to prevent stuck transactions)`; abc: refused |

## KNOWN

| row | divid | irondivid | reason |
|---|---|---|---|
| `estimatepriority 2` | -32601 `Method not found` | -1 | irondivid answers -1 (no estimate), kept with `estimatefee` and `estimatesmartfee` for Bitcoin-family clients (`docs/divid-differences.md` R1) |
| `getinfo paytxfee`, `getwalletinfo paytxfee` (at every setting) | absent | 0.0 and 0.0001 | irondivid adds the field (`getinfo`: also KNOWN in `scripts/chain-replies`; `getwalletinfo`: `docs/divid-differences.md` R4); `divi/src/rpcmisc.cpp:136-157` and `divi/src/rpcwallet.cpp:2873-2907` have no `paytxfee` |
| `start -minrelaytxfee=0`, `=abc`, `-maxtxfee=0`, `=abc` | the error, then exit -6 | the same error, exit 1 | divid aborts (SIGABRT) in the shutdown after this early `InitError`: `PrepareShutdown`'s `FlushStateToDisk` (`divi/src/init.cpp:381`) asserts in `ChainstateManager::Get` (`divi/src/ChainstateManager.cpp:102`) before the chain state exists (also KNOWN in `scripts/restart-options`) |
