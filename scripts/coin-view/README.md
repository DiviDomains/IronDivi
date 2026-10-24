# The coin view next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and a fresh irondivid on regtest, irondivid following divid, and
compares what each says about the coin view: `gettxout` for one output after another across its life, `verifychain`,
`gettxoutsetinfo`, `getdifficulty` and the difficulty fields of `getblockchaininfo` and `getinfo`, and the
`-checklevel`/`-checkblocks` start options. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/coin-view/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/coin-view/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about four minutes and is stopped after 10 minutes. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in each node's 0600 `divi.conf`.

## Nodes and steps

divid listens on 127.0.0.2 and mines; irondivid dials it (`connect=`) with `disablewallet=1`. Both run with
`staking=0`.

1. `getdifficulty`, the difficulty of `getblockchaininfo` and `getinfo`, and `gettxoutsetinfo` at height 0, at each
   height from 98 to 106 (the last proof-of-work block on regtest is 100, `chainparams.cpp:405`; the blocks after it
   are staked), and at 125.
2. At 106: `gettxout` of the coinbase of block 100 and of the tip's coinstake (both younger than the 20 blocks of
   maturity, `chainparams.cpp:479`), and of the tip's coinbase (an empty output).
3. At 126: a vault funding (`fundvault`), a send A to an address of divid's wallet, a block with both; then a
   spend of A's output and a send B, both left in the mempool.
4. `gettxout` with no flag, `includemempool` true and false for: B's outputs (unconfirmed), A's output spent in the
   mempool and its other output, the mempool spend's output, A's input (spent in a block), a mature coinbase, a
   mature coinstake, the vault output, an index past the last output; and wrong arguments (unknown txid, txid not
   hex, too short or empty, negative index, index as text or 1.5, `includemempool` as text or 1, txid a number, one,
   none or four arguments).
5. The same `gettxout` rows (and `getrawmempool`) after `invalidateblock` of A's block on both nodes, after
   `reconsiderblock`, after a restart of both, and after a start of both with `-reindex`. After a start divid's
   wallet takes its unconfirmed sends back into its mempool without relaying them; the script sends each of them
   again with `sendrawtransaction` on divid, which relays it.
6. `verifychain` with no arguments, level 0 to 4 with depth 10, level 4 with depth 0, 1, the tip height, one more
   and -1, and wrong arguments; again after both nodes are killed and started.
7. Start with `-checklevel` 4, 0 and `abc`, and with `-checkblocks` 0, 1, 50, -1, `abc` and 99999999: started (and
   the block count), or the exit code and the error line.

How a row compares: the same outcome (a result, or an error with the same code and message); for a result every
member in the same order, of the same JSON type, with the same value as the node printed it (amounts are compared
as text, so `1250.00000000` and `1250` differ).

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c): `gettxout`
`rpcblockchain.cpp:330-402`, `gettxoutsetinfo` `:293-328`, `verifychain` `:404-423`, `getdifficulty` `:64-76`,
`VerifyDB` `verifyDb.cpp:66-162`, `-checklevel` `init.cpp:783-784`, `-checkblocks` `init.cpp:1116`.

## KNOWN differences

- `gettxout: fields divid lacks`: irondivid adds `coinstake` after `coinbase`; `gettxoutsetinfo: fields divid lacks`:
  irondivid adds `bogosize` after divid's members. The rows compare the replies without them (the same rows as in
  `scripts/chain-replies`).
- `verifychain 10` (one argument), before and after the unclean stop: not sent to divid. divid reads the depth from
  the second argument whenever there is one (`rpcblockchain.cpp:419-420`), so with one argument it reads past the
  end of the array; it crashed on `verifychain 0` and answered a type error for `verifychain "x"` here. The row
  shows irondivid's answer.
- `start -checklevel=4`, `=0`, `=abc`: the same message on both ("Error: Unsupported argument -checklevel found.
  Checklevel must be level 4.", `init.cpp:783-784`); divid then aborts (SIGABRT) in the shutdown after this early
  InitError, as in `scripts/restart-options`; irondivid exits 1.

## Proving a difference is caught

`COIN_VIEW_INJECT=<row name>` changes irondivid's reply of that row before it is compared, e.g.
`COIN_VIEW_INJECT='gettxout vault 0'`: that row prints `FAIL` and the run exits 1.
