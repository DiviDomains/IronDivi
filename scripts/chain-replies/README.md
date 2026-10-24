# Blockchain and raw-transaction RPC replies next to Divi Core

`run.sh` starts a fresh Divi Core 3.0.0 `divid` and an irondivid restored from divid's phrase on one regtest chain
that divid mines. The chain has sends, a vault, a version-2 transaction, an OP_META output carrying 1 DIVI, and a
reorganization that leaves a stale block. It makes the same calls on both nodes, the ones explorers and exchanges
use, and compares the replies field by field: names, types, values in divid's units, and error codes and texts. It
does this before and after a restart of both nodes. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`. The exit code is the number of FAILs. It is 255 for a usage error, an interrupted
run, or a run over 10 minutes.

```sh
scripts/chain-replies/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/chain-replies/run.sh target/release ~/divi-3.0.0/bin 54246 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.1 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

**Run time and clean-up.** A run takes about 15 seconds and is stopped after 10 minutes. However it ends, both nodes
are stopped and their directories deleted.

**Requirements.** bash and python3 (standard library only).

**The phrase.** It is read from divid's `dumphdinfo` reply and handed to irondivid in its environment
(`WALLET_MNEMONIC`). It is never printed, written to a file or put on a command line.

## Nodes and steps

divid listens and irondivid dials it (`connect=`), so both see one chain, and both wallets own the same keys. Both run
with `staking=0` and `txindex=1`. divid runs with `acceptnonstandard=1`, so it takes the version-2 transaction;
irondivid gets that transaction in a block.

1. divid mines 40 blocks.
2. A block with: a send, a `fundvault` vault funding, and two funding sends. One of them (`sendmany`) also pays an
   address nobody holds a key for, so that transaction keeps an unspent output for good.
3. A block with a version-2 transaction and a transaction with an output of 1 DIVI to an OP_META script. Both are raw
   transactions made on divid (`createrawtransaction`, then the version or the output is set,
   `signrawtransaction`, `sendrawtransaction`).
4. **Reorganization.**
   1. A block with a send.
   2. divid `invalidateblock`s it and mines two blocks, which take the send again.
   3. divid `reconsiderblock`s it.
   4. irondivid follows. The old block stays known on both as a stale branch.
5. A send left in both mempools. The coin the raw transactions spend is locked on divid (`lockunspent`), so no send takes
   it.
6. The replies below. Then both nodes are stopped and started again, the mempool send is given back to a node that
   does not hold it any more (`sendrawtransaction`), and the replies run again (`after restart:` rows).

## Rows

| call | forms |
|---|---|
| `getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getdifficulty`, `getinfo` | none |
| `getchaintips` | none (tips sorted by hash: the active tip and the stale block) |
| `getblockhash` | 0, the tip, past the tip, -1, `"1"`, 1.5, none |
| `getblock` | tip; tip true/false; genesis; the block with the sends; the stale block; tip 1; unknown hash; not a hash; none |
| `getblockheader` | tip; tip false; the stale block; unknown hash; none |
| `gettxout` | unspent, spent, coinbase, version-2, OP_META, vault, two mempool outputs, past the last output, unknown transaction, each with includemempool true and false; default includemempool; not a hash; vout as text; none |
| `gettxoutsetinfo` | none |
| `verifychain` | none, `3 10`, `4 0` |
| `getrawtransaction` | a send 0/1/none, version-2, OP_META, coinbase, vault, mempool, verbose `true`, unknown transaction, not a hash, none |
| `createrawtransaction` | one output; two outputs (not in name order) as an object and as an array; no inputs; bad address; txid not hex; missing vout; negative vout; negative amount; inputs not an array; none |
| `decoderawtransaction` | created, signed, version-2, OP_META, coinbase; not hex; not a transaction; none |
| `decodescript` | pay-to-key-hash, 2-of-2 multisig, OP_META, empty; not hex; none |
| `signrawtransaction` | complete; one input unknown (incomplete, with errors); a coin of the keyless address (incomplete); sighash `ALL`; bad sighash; not hex; none |
| `sendrawtransaction` refusals | already in the chain; unsigned; a spent input; a mempool conflict; already in the mempool; not hex; not a transaction; none |
| one argument too many | every call above, one argument past divid's count |

**How a row compares.** The two nodes must have the same outcome: a result, or an error with the same code and
message. For a result, every field must match in name, JSON type and value, with list items in divid's order. Reals
are compared as the text of the number, so `1.0` and `1.00000000` differ, and so do a real and an integer.

**Wrong argument count.** divid answers -1 with the call's whole help text. irondivid's help texts are shorter, so for
these rows only the code is compared (both -1), not the text (docs/divid-differences.md, "Not listed here"). A call
that irondivid answers where divid refuses still FAILs.

**Not called.** `verifychain` with a text argument: divid 3.0.0 sometimes stops (the process ends) on it, while
answering `-1 "value is type array, expected int"` at other times.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).

## KNOWN differences

**By design: extra fields.** Each is compared without the fields; the run checks that they are still the only extra
ones (`<call>: fields divid lacks` rows).

- `getblockchaininfo`: fullhistorypeers, lastblockfetch, mediantime, pruned, pruneheight, snapshotbase, warnings,
  winnersstripheight (docs/divid-differences.md R3).
- `getblock`: mediantime, nTx, as Bitcoin Core gives them (divid: `blockToJSON`, `JsonBlockHelpers.cpp:38-77`).
- `getblockheader`: hash, confirmations, height, mediantime, difficulty, chainwork, nTx (divid has 6 fields:
  `blockHeaderToJSON`, `JsonBlockHelpers.cpp:80-91`).
- `gettxout`: coinstake (divid: coinbase only, `rpcblockchain.cpp:398-399`).
- `gettxoutsetinfo`: bogosize, the size of irondivid's own UTXO records (divid: `rpcblockchain.cpp:319-325`).
- `decoderawtransaction`: valueSat beside value on each output, as divid's getrawtransaction writes it
  (`rpcrawtransaction.cpp:96-97`). divid's decoderawtransaction writes value only (`TxToJSON`,
  `JsonTxHelpers.cpp:66`).
- `decodescript`: hex, the script given (divid: `rpcrawtransaction.cpp:556-563`).
- `getinfo`: keypoololdest, keypoolsize, paytxfee (divid: `rpcmisc.cpp:136-157`).

**By design: argument types irondivid takes too.**

- `getblock <hash> 1`: irondivid takes verbosity 0, 1 or 2, as Bitcoin Core does (2: the transactions decoded).
  divid reads a bool (`rpcblockchain.cpp:216`).

**Open, not closed yet.** These are listed so the run stays usable. A fix turns the row into a FAIL until it is
taken out here and in `KNOWN` in `check.py`.

- `createrawtransaction` with the outputs as an object: irondivid writes the outputs sorted by address, not in the
  order given, so the transaction differs from divid's.
  - **Cause:** the RPC layer parses each request into serde_json maps, which keep member names sorted (no
    `preserve_order` in Cargo.toml; docs/divid-differences.md R6).
  - divid keeps the order given (`rpcrawtransaction.cpp:400-410`).
  - The array form (`[{"addr": n}, ...]`) keeps the order on irondivid, and that row passes.
- `sendrawtransaction` of an unsigned spend (open: rpc-left, RPC-LEFT.md row 8): irondivid answers -25 `""`, divid
  -26 `"16: mandatory-script-verify-flag-failed (...)"`.

## Proving a difference is caught

- `CHAIN_REPLIES_INJECT=<row name>` changes irondivid's reply of that row before it is compared. For example,
  `CHAIN_REPLIES_INJECT='getblockcount'` makes that row print `FAIL` and the run exit 1. An error reply gets text
  added to its message.
- `CHAIN_REPLIES_DUMP=<dir>` writes both replies of every row that differs to `<dir>`, for looking into a FAIL.
