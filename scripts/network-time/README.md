# Clocks and block times, next to Divi Core

`run.sh` runs a Divi Core 3.0.0 `divid` and an irondivid side by side on regtest, drives the same steps on each and
compares the replies. Times are compared relative to each node's own mocked clock, a block's median time past or
the block offered, since each node of the first pair mines its own chain.

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the Divi Core line that justifies it;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 30 minutes).

```sh
scripts/network-time/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a debug build of this tree
cargo build -p irondivid
scripts/network-time/run.sh target/debug ~/divi-3.0.0/bin 46600 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+9` on 127.0.0.2 (p2p and RPC of each node).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

Each node's RPC password is a fresh random value written only to its `divi.conf`. A run takes about 4 minutes.
Needs bash and python3 (standard library only). `NETWORK_TIME_INJECT=<row name>` makes that row differ, to show a
difference is caught. Pointing both directories at Divi Core (a directory where `irondivid` is a link to `divid`)
checks the script itself: every row passes.

## Rows

1. **setmocktime:** the replies to no argument, a string, a real, null, two arguments, and 0 (rpcmisc.cpp:525-545);
   `timeoffset` in getinfo and getnetworkinfo, and getpeerinfo, with no peer.
2. **Blocks made on a mocked clock** (each node alone, three days back): a work block's time is the clock
   (BlockFactory.cpp:77); on a clock set before the tip it is the median time past + 1 (BlockProofProver.cpp:36).
   Then work blocks to 100, the clock a minute on before each.
3. **The stake window** (PoSTransactionCreator.cpp:335-341): a stake block a minute on is within 45 s before the clock
   and past the median time; with the clock 177 s behind the median time there is one second to stake at, 178 s and
   300 s none (`-25 failed to generate a valid block`); at 100 s behind, a block, when the kernel is found, is
   inside the window.
4. **Sporks:** `spork active` with the clock at 4070908800 and one second later, when the default-off sporks turn on
   (IsSporkActive on GetAdjustedTime, spork.cpp:379).
5. **Wallet and mempool times on a clock two hours ahead of the system's:** a send's `getrawmempool true` time, its
   `time` and `timereceived` before and after a block (nTimeReceived = GetAdjustedTime, SpentOutputTracker.cpp:47;
   smart time, wallet.cpp:1052-1086; the pool's entry time, MempoolConsensus.cpp:386); a coinstake's times.
6. **Blocks a third node (a divid) made, offered from a script peer** (an inv, then the header and block on request) to
   a fresh divid and irondivid:
   - 99 blocks two days old on the system clock: all taken, and how often `-blocknotify` ran;
   - a work block 7201 s ahead of each node's clock (refused `time-too-new`), then 7200 s ahead (taken), and a stake
     block 181 s and then 180 s ahead (BlockCheckingHelpers.cpp:29-31, Settings.cpp:215-218). A block refused for
     its time is not marked invalid, so the same block is taken once it is inside the limit.
   - how often `-blocknotify` ran once the work block, the first within 6 hours of the clock, ended the initial
     block download: divid signals that tip and no earlier one (ChainExtensionService.cpp:556-565).

What `net-time` covers is not repeated: the offset from peers' version messages, its cap and warning, and the
2-hour limit on the network-adjusted clock.

## KNOWN

None. (`blocknotify for blocks older than 6 h` was one; irondivid now runs `-blocknotify` only out of the
initial block download, as divid does.)
