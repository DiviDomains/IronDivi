# A long, busy chain synced both ways, next to Divi Core

`run.sh` builds one seeded regtest chain of about 3,000 blocks on Divi Core 3.0.0 `divid`, every block from 101
carrying transactions. Then it compares, with irondivid:

- a sync from scratch both ways: irondivid from divid, then a divid from that irondivid alone;
- a sync stopped twice on each node (a clean stop, then a kill) and started again;
- `-reindex` on each node;
- a wallet restored from the chain owner's phrase with `-rescan` on each node.

The outcomes are compared, and the wall times are printed. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with the wall times and `FAILS <n>`; the exit code is the number of FAILs (255: usage error,
interrupted, or over 3 hours).

```sh
scripts/large-sync/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/large-sync/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+9` on 127.0.0.2, p2p and RPC for up to five nodes.
  `<port-base>+49` is used as a peer that does not exist.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.
- `LARGE_SYNC_SEED` (5) seeds every choice; `LARGE_SYNC_BLOCKS` (3000) is the chain's height.
- `LARGE_SYNC_SAVE=<dir>` copies the built chain (the owner's datadir, wallet included) to `<dir>`;
  `LARGE_SYNC_CHAIN=<dir>` starts from such a copy instead of building a chain, so runs compare on one chain.
  Building takes about 45 minutes. A saved chain holds the run's throwaway wallet: keep it private and delete it
  when done.
- `LARGE_SYNC_KEEP=1` keeps the work directory (datadirs and logs) at the end.

A run from a saved chain takes about 8 minutes; building the chain adds about 45. However it ends, every node is
stopped and the work directory deleted. Needs bash and python3 (standard library only). The owner's phrase is read
from divid's `dumphdinfo` reply. It goes to the restoring divid in its 0600 `divi.conf` and to irondivid in its
environment (`WALLET_MNEMONIC`), and is never printed or put on a command line. Every key is a throwaway of the run.

## The chain

One divid owner (`txindex`) and one divid vault manager build it; the owner makes each block (`setgenerate 1`):

- the first 100 blocks by proof of work, then 200 of the owner's addresses funded by `sendmany`;
- every block: a raw spend with change to the owner's own address;
- every fifth block: a receive of 30 outputs;
- every 30 blocks: a `sendtoaddress` and a `sendmany`;
- 2-of-2 multisig: one funded every tenth block (a P2SH output); a block later the oldest of those waiting is
  spent by `signrawtransaction`, once more than three wait;
- `fundvault` every 50 blocks, and blocks staked by the vault manager from those vaults;
- every 500 blocks: one transaction of 2,800 outputs (about 95 kB, near divid's 100,000-byte limit,
  `defaultValues.h:54`) and one with 390 bare 1-of-1 multisig outputs (7,800 sigops, near the 8,000 a transaction
  may have, `MempoolConsensus.cpp:372-380`);
- the regtest lottery (every 200 blocks from 101) and treasury (every 201 from 102) heights are passed
  many times (`chainparams.cpp:407-410`).

The run prints the counts of each kind as it builds.

## Rows

Core paths are under `divi/src/` of the Divi Core source at v3.0.0. A sync waits for the node to reach the
chain's tip; a node whose height stops moving for 10 minutes fails the row (or the run, for the first syncs).

| part | rows |
|---|---|
| sync from scratch | irondivid synced from divid, then a divid synced from that irondivid alone, each against the node it synced from: the tip (height, hash), the hash at every 100th height, `gettxoutsetinfo`, `getchaintips`, `getblock` for about 20 heights (1, 100-102, 250, 400, 1001, the middle, the last two, and ten seeded ones) |
| sync stopped | a divid and an irondivid each sync from irondivid, are stopped cleanly at one seeded height and killed at another (the same two heights for both), and started again each time (with `-reindex` if a start fails, as `scripts/unclean-stop`): started again, reached the tip, `gettxoutsetinfo`; and irondivid's `gettxoutsetinfo` against the chain's |
| `-reindex` | each node alone (no peers): the tip and `gettxoutsetinfo` |
| restart | each node stopped and started: the tip |
| restored wallet | each node restarted with an empty wallet restored from the owner's phrase and `-rescan`: `getbalance`, the `listtransactions` entries, the `listunspent` coins, `getwalletinfo` `txcount` |

A divid that syncs a chain longer than one batch of block inventory (500) from a peer that makes no new block
stops one block short of the tip: its peer sends the tip at the end of each batch, divid drops a block whose parent
it lacks and asks for it again only with its next `getblocks` (`main.cpp:822-833`), and none comes once it has the
rest. It does so from divid and from irondivid alike (a row compares the height it waited at). A node that waits a
block short for 60 seconds is started again, which fetches the tip; its sync time is taken to where it waited.
irondivid keeps such a block and reaches the tip.

Printed, not compared: the wall time of each (the sync from start to the tip; restart to the first RPC answer;
`-reindex` to the tip; the restore until the wallet answers), and irondivid's time over divid's.

Left out of the comparisons:

- `gettxoutsetinfo` `bytes_serialized` and `hash_serialized`, made from each node's own files (as
  `scripts/coin-locks`, `scripts/unclean-stop`);
- the fields irondivid adds (`KNOWN` by design in `scripts/chain-replies`): `getblock` `mediantime` and `nTx`,
  `gettxoutsetinfo` `bogosize`; and `getblock` `confirmations`, which moves with each node's tip.

## Timing

irondivid's `-reindex` rebuilds its indexes from the blocks it has stored and keeps its chainstate
(`crates/divi-node/src/node.rs:342-361`); divid's replays every block file and rebuilds its chainstate. The
outcome is compared; the two times measure different work.
