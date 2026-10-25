# Network-adjusted time, next to Divi Core

`run.sh` runs a fresh pair of regtest nodes per scenario, one pair at a time: a Divi Core 3.0.0 `divid` and an
irondivid. Script peers connect to each, each from an address of its own (127.0.0.10 and up, since divid takes one
sample per address). Each sends a version message whose time is a chosen number of seconds off the clock, completes
the handshake, answers pings and stays connected.

Each row prints one line:
- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the Divi Core line that justifies it;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid.

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 15 minutes).

```sh
scripts/net-time/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/net-time/run.sh target/release ~/divi-3.0.0/bin 53950 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2: divid, irondivid, and the divid that makes the
  future blocks.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about 3 minutes and is stopped after 15. However it ends, every node is stopped and its directory deleted.
Needs bash and python3 (standard library only). `NET_TIME_INJECT=<row name>` makes that row differ, to show a
difference is caught.

## What divid does (Divi Core 3.0.0, `divi/src/`)

- **The sample:** AddTimeData runs at the end of each version message, inbound and outbound (main.cpp:465), with the
  connection's address (main.cpp:465, `pfrom->GetCAddress()`).
  - The sample is the peer's time less ours (timedata.cpp:47).
  - Each address gives one sample for the life of the node, its port aside (`setKnown`, timedata.cpp:50-53).
- **The filter:** `CMedianFilter(200, 0)` holds the newest 200 samples and starts with one 0, our own clock
  (timedata.cpp:56, timedata.h:28-45).
- **The offset:** with at least 5 samples and an odd number of them, the median, when it is under 70 minutes; past
  that 0 (timedata.cpp:77-85). With an even count it is left as it was.
- **The warning:** past the cap, once, when no sample is within 5 minutes of ours (and not on it):
  `Warning: Please check that your computer's date and time are correct! If your clock is wrong DIVI Core will not
  work properly.` (timedata.cpp:86-101).
  - It goes in the log and is the miscellaneous warning shown as getinfo's and getmininginfo's `errors`
    (Warnings.cpp:35-39, rpcmisc.cpp:156, rpcmining.cpp:242).
  - getnetworkinfo has no warnings field (rpcnet.cpp:368-385).
- **Reported:** `timeoffset` in getinfo (rpcmisc.cpp:147) and getnetworkinfo (rpcnet.cpp:374).
- **Users of GetAdjustedTime (GetTime() + the offset, timedata.cpp:35-38):**
  - the future-block limit: 2 h for PoW, 180 s for PoS (BlockCheckingHelpers.cpp:29-31, Settings.cpp:215-218);
  - block times made (BlockFactory.cpp:77, BlockProofProver.cpp:36, :69);
  - the coinstake time and search window (PoSTransactionCreator.cpp:335-341);
  - coin age (wallet.cpp:1452, :1477);
  - mempool time locks (MempoolConsensus.cpp:61, TransactionFinalityHelpers.cpp:16-17);
  - the wallet's received time (SpentOutputTracker.cpp:47);
  - the version time sent to an inbound peer (Node.cpp:995-996);
  - addr times and the address manager (main.cpp:536-545, addrman.h:97-560, addrman.cpp:258, net.cpp:1147);
  - masternode, spork and alert times (masternodeman.cpp, spork.cpp, alert.cpp).
- **On GetTime:** ban times (net.cpp:760, :1283), the staker's stale-tip and attempt checks (CoinMinter.cpp:68, :89,
  PoSTransactionCreator.cpp:236), and the addr relay day (net.cpp:1508).

## Rows

1. **Seven peers, one at a time, with skews of +600, +900, +1200, -300, +1500, +1800 and -4800 s.**
   - After each peer: timeoffset in getinfo and getnetworkinfo.
   - After each peer: the time of the version message the node sent that inbound peer, less the peer's clock.
   - Then the peers leave, and a peer from an address already sampled comes with -4000 s.
   - Then the warning fields.
2. **Four peers at +80 min:** timeoffset and the warning fields; then two more (six) and timeoffset.
3. **+60 s and three peers at -80 min:** timeoffset and the warning fields (a peer within 5 minutes holds the warning
   back).
4. **The future-block limit.** A divid with its clock set ahead makes a PoW block on genesis, 2 h 30 min ahead and then
   1 h 30 min ahead.
   - With four peers at +1 h, the 2 h 30 min block is offered to each node; with four at -1 h, the 1 h 30 min one.
   - The block goes from a script peer: an `inv`, then the header on `getheaders` and the block on `getdata`.
   - Row: each node's block count after.

Offsets are compared within 1 s of each other, and the version time within 2 s. A node reads its clock a moment after
the peer wrote its time, so the two nodes can see the same skew a second apart.

## KNOWN

None differ.
